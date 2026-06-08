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


# installing tools with apt
apt install ffuf -y
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

# system demon inits
systemctl start docker
systemctl enable docker

# pip installtions
python3 -m pip install dnsgen
python3 -m pip install recollapse

# pipx installtions 
pipx install uro


echo "unalias gau" >> ~/.zshrc

# installing tools with go
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/ImAyrix/fallparams@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/tomnomnom/anew@latest 
go install -v github.com/bitquark/shortscan/cmd/shortscan@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# gem installtions 
gem install wpscan


# clone the repoes with git 
git clone https://github.com/Sh1Yo/x8 ~/git/x8
git clone https://github.com/NakuTenshi/ASNinformer/ ~/git/tools/ASNinformer
git clone https://github.com/NakuTenshi/JSHound/ ~/git/tools/JSHound
git clone https://github.com/nakuTenshi/wbf/ ~/git/tools/wbf
git clone https://github.com/nakuTenshi/RoboBack ~/git/tools/RoboBack

cd ~/git/tools/ASNinformer
bash ./install.sh

cd ~/git/tools/JSHound
bash ./install.sh

cd ~/git/tools/wbf
bash ./install.sh

cd ~/git/tools/RoboBack
bash ./install.sh


# docker installtions
docker build -t x8 ~/git/x8/.

# update the template of nuclei
nuclei -update
nuclei -update-templates

# downloading wordlist
#mkdir ~/myWordList
#curl http://wordlisthub.pythonanywhere.com/api/download/ -o ~/myWordList/myWordList.zip
#unzip ~/myWordList/myWordList.zip

cd ~
echo "[+] the installtion of tools is done";
echo "[+] everything is ready";
