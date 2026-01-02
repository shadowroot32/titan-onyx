#!/bin/bash
set -e

echo "[*] INSTALLING TITAN-VALHALLA (RENGINE CLONE)..."

# 1. System Dependencies
sudo apt update
sudo apt install -y build-essential libpcap-dev jq git chromium-driver ffuf whois python3-pip unzip libcurl4-openssl-dev libxml2-dev sqlite3 libssl-dev

# 2. Go Setup
sudo rm -rf /usr/local/go
wget -q https://go.dev/dl/go1.22.1.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz
rm go1.22.1.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin:~/go/bin

# 3. Install Tools
echo "[+] Installing Security Tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/sensepost/gowitness@latest
go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

# 4. Global Path Link
echo "[+] Linking tools to /usr/local/bin..."
TOOLS=("subfinder" "dnsx" "naabu" "httpx" "nuclei" "katana" "assetfinder" "anew" "waybackurls" "gau" "gowitness" "crlfuzz")
for tool in "${TOOLS[@]}"; do
    sudo rm -f /usr/local/bin/$tool
    sudo cp ~/go/bin/$tool /usr/local/bin/
done

# 5. Rust & Python
if command -v cargo &> /dev/null; then
    cargo install feroxbuster
    sudo cp ~/.cargo/bin/feroxbuster /usr/local/bin/ 2>/dev/null || true
fi

pip3 install rich pyyaml requests psutil arjun --break-system-packages

# 6. Update
nuclei -update-templates
echo "[✔] VALHALLA READY."