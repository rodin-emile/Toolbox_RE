#!/bin/bash

# Vérifier si l'utilisateur a les droits sudo
if [ "$(id -u)" != "0" ]; then
    echo "Ce script doit être exécuté avec les privilèges sudo."
    exit 1
fi

# Fonction pour vérifier l'état des commandes d'installation
check_status() {
    if [ $? -ne 0 ]; then
        echo "Erreur : Échec de l'exécution de la commande. Veuillez vérifier les logs ci-dessus."
        exit 1
    fi
}

# Mise à jour des paquets disponibles
echo "Mise à jour des paquets disponibles..."
apt update -y
check_status

# Installation des paquets nécessaires
echo "Installation des paquets nécessaires..."
apt install -y python3 python3-pip libssl-dev libffi-dev python3-dev build-essential gcc git
check_status

# Installation des bibliothèques Python nécessaires
echo "Installation des bibliothèques Python..."
pip3 install --upgrade pip
pip3 install requests python-nmap zxcvbn-python paramiko pymetasploit3 pandas matplotlib reportlab flask
check_status

echo "Installation des prérequis terminée avec succès."

# Dépendances Python manquantes
cat <<EOF > requirements.txt
requests
python-nmap
zxcvbn-python
paramiko
pymetasploit3
pandas
matplotlib
reportlab
flask
EOF
pip3 install -r requirements.txt
check_status
