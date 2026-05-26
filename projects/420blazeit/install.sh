#!/bin/bash 
if command -v  uv > /dev/null; then 
        echo "[+] found uv"
else
        echo "[!] Please install uv from https://docs.astral.sh/uv/getting-started/installation/" 
        exit 1
fi

if [ -d ".venv" ]; then
        echo "[+] found venv"
else
        echo "[+] configuring venv ..."
        uv venv
fi

source .venv/bin/activate
echo "[+] installing requirements..."
uv pip install -r requirements.txt
echo "[+] building docker image..."
docker build . -t "420blazeit"
echo "[+] install complete!"
