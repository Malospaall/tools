#!/bin/bash

set -e

echo "[+] Updating packages..."

sudo apt update

sudo apt install -y \
amass build-essential certipy-ad coercer dbeaver dkms dmitry docker-compose docker.io \
enum4linux evil-winrm ffuf firebird-utils gobuster gvm hashcat htop hydra ike-scan \
impacket-scripts john joomscan ldap-utils linux-headers-$(uname -r) metasploit-framework \
mitm6 net-tools netexec network-manager-l2tp network-manager-openvpn nikto nmap nuclei \
onesixtyone python3-pip remmina responder seclists smbclient snmp snmpcheck spiderfoot \
strongswan sqlmap sqsh subfinder sublist3r theharvester whois wifite wireshark wpscan

echo "[+] Enabling docker..."

sudo systemctl enable docker --now
sudo usermod -aG docker $USER

echo "[+] Removing default user directories..."

rm -rf ~/Documents ~/Music ~/Pictures ~/Public ~/Templates ~/Videos

echo "[+] Setting GRUB timeout..."

sudo sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=1/' /etc/default/grub
sudo update-grub

echo "[+] Downloading config archive..."

curl -L https://raw.githubusercontent.com/Malospaall/tools/main/Linux/kali-bootstrap/kali-config.tar.gz -o /tmp/kali-config.tar.gz

echo "[+] Extracting configs..."

tar -xzf /tmp/kali-config.tar.gz -C ~

rm /tmp/kali-config.tar.gz

echo "[+] Setup completed."
