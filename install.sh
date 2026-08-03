#!/usr/bin/env bash

#apt update && apt upgrade -y

shell=$(echo $SHELL | cut -d"/" -f4)
shell_path="$HOME/.${shell}rc"

if [[ "$EUID" -ne 0 ]]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

for file in ./scripts/*.sh; do
    
    [[ -e "$file" ]] || continue

    name="$(basename "${file%.sh}")"

    cp -r "$file" "/bin/$name"

done

for file in ./scripts/*.py; do

    [[ -e "$file" ]] || continue

    name="$(basename "${file%.py}")"

    cp -r "$file" "/bin/$name"

done

# installtion cargp
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env


# installing go 
GO_VERSION=$(curl -s https://go.dev/VERSION?m=text | head -n1)
wget -q "https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
sudo tar -C /usr/local -xzf /tmp/go.tar.gz
grep -q '/usr/local/go/bin' ~/.profile || \
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
export PATH=$PATH:/usr/local/go/bin


# installing tools with apt
apt install ffuf -y
apt install adb -y 
apt install fastboot -y
apt install git -y
apt install curl -y
apt install git -y 
apt install pipx -y
apt install python3-pip -y
apt install python3-venv -y
apt install unzip -y
apt install docker -y
apt install docker.io -y
apt install nmap -y 
apt install whois -y
apt install crunch -y
apt install wireshark -y
apt install build-essential -y 
apt install ruby-dev -y
apt install pkg-config libssl-dev build-essential -y

# system demon inits
systemctl start docker
systemctl enable docker

# pip installtions
python3 -m pip install dnsgen
python3 -m pip install recollapse

# pipx installtions 
pipx install uro

# installing tools with go
go install github.com/tomnomnom/unfurl@latest
go install -v github.com/tomnomnom/anew@latest 
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/ImAyrix/fallparams@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/bitquark/shortscan/cmd/shortscan@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest


# gem installtions 
gem install wpscan


# clone the repoes with git 
git clone https://github.com/NakuTenshi/ASNinformer/ /home/naku/code/tools/ASNinformer
git clone https://github.com/nakuTenshi/wbf/ /home/naku/code/tools/wbf
git clone https://github.com/nakuTenshi/RoboBack /home/naku/code/tools/RoboBack
git clone https://github.com/NakuTenshi/JSAgent/ /home/naku/code/tools/JSAgent
git clone https://github.com/NakuTenshi/x9 /home/naku/code/tools/x9
git clone https://github.com/NakuTenshi/domHound /home/naku/code/tools/domHound
git clone https://github.com/NakuTenshi/0x00Tower /home/naku/code/tools/0x00Tower
git clone https://github.com/NakuTenshi/dorkgen /home/naku/code/tools/dorkgen
git clone https://github.com/NakuTenshi/JWTKeyCracker /home/naku/code/tools/JWTKeyCracker
git clone https://github.com/NakuTenshi/hookWord /home/naku/code/tools/hookWord
git clone https://github.com/NakuTenshi/UnCDN /home/naku/code/tools/UnCDN
git clone https://github.com/NakuTenshi/cert2android /home/naku/code/tools/cert2android

# cargo installtions
cargo install x8

# update the template of nuclei
nuclei -update
nuclei -update-templates

# install claude 
curl -fsSL https://claude.ai/install.sh | bash

cd /home/naku
echo "[+] the installtion of tools is done";
echo "[+] everything is ready";
