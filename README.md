# v2link-client

Linux desktop client for V2Ray-style links (vmess://, vless://, trojan://, ss://) built with Python 3.11+ and PyQt6.

## Development

sudo apt update
sudo apt install -y python3-venv python3-full

# 2) Create a venv inside the project
python3 -m venv .venv

# 3) Activate it
source .venv/bin/activate

# 4) Upgrade pip inside the venv (safe)
python -m pip install --upgrade pip

# 5) Install your deps
pip install -r requirements.txt
- Create a virtual environment and install dependencies:
  - `pip install -r requirements.txt`
- Run:
  - `./scripts/dev_run.sh`

## Notes

- sing-box binaries should be placed under:
  - `resources/sing-box/linux-amd64/sing-box`
  - `resources/sing-box/linux-arm64/sing-box`
