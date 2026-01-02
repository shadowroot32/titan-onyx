#!/bin/bash
set -e # Stop jika ada error

echo "[+] MEMULAI INSTALASI TITAN-ONYX (PROJECT RENGINE KILLER)..."

# 1. Update & Install Core Libs
sudo apt update
sudo apt install -y build-essential libpcap-dev jq git chromium-driver ffuf whois python3-pip unzip ruby-full libcurl4-openssl-dev libxml2-dev libxslt1-dev ruby-dev zlib1g-dev libgmp-dev cargo sqlite3 libssl-dev

# 2. Reset & Install Go (Versi Terbaru)
echo "[+] Menginstall Golang..."
sudo rm -rf /usr/local/go
wget -q https://go.dev/dl/go1.22.1.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz
rm go1.22.1.linux-amd64.tar.gz

# 3. Setup Environment Variables
echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOROOT/bin:$GOPATH/bin:$HOME/.cargo/bin' >> ~/.bashrc
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.cargo/bin

# 4. Install Arsenal (Tools Inti)
echo "[+] Menginstall Tools Recon & Attack..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/sensepost/gowitness@latest

# 5. Rust & Python Tools
echo "[+] Menginstall Tools Pendukung..."
cargo install feroxbuster
pip3 install -r requirements.txt --break-system-packages

# 6. Finalisasi
echo "[+] Update Database Vulnerability..."
nuclei -update-templates
mkdir -p wordlists
wget -nc https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt -O wordlists/raft.txt

echo "[✔] INSTALASI SELESAI. SILAKAN JALANKAN: python3 titan.py <target>"