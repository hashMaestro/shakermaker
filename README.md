# Shakermaker

**Status:** unfinished experimental proof of concept — not production code.

Shakermaker is informal research software for studying 802.11 frame handling in controlled environments. It was written as exploratory work and has **not** been through systematic testing, code review, or hardening. **Do not** use it for operational security work, client engagements, or any purpose outside explicit, authorized research.

## Disclaimer

- This project is provided **for authorized security research and education only**, on systems and networks you own or have **written permission** to test.
- It is **not** suitable for real-world assessments, red-team operations, or compliance-driven testing.
- Authors and contributors **disclaim all liability** for misuse, damage, or legal consequences. **You** are responsible for complying with applicable laws and policies.
- The code may be incorrect, incomplete, or unsafe; treat it as a lab curiosity, not a tool you can rely on.

See the module docstring in `shakermaker.py` for the full disclaimer text.

## Requirements

- Python 3
- Linux (or similar Unix with raw 802.11 support as used here)
- [Scapy](https://scapy.net/)
- Root privileges for raw send/receive
- A wireless interface already in **monitor mode** and bound to the **same channel** as the **target router** (this tool does not configure monitor mode for you)

## Install

```bash
pip install -r requirements.txt
```

## Usage (illustrative only)

```bash
sudo python3 shakermaker.py --bssid AA:BB:CC:DD:EE:FF --target 11:22:33:44:55:66 --iface wlan0mon --burst 1
```

Replace MACs and interface names with values appropriate to **your** lab and authorization.

## License

Unless otherwise noted, you may treat accompanying material as released for research and educational use at your own risk. If you add a formal open-source license file for your fork, align it with your organization’s requirements.
