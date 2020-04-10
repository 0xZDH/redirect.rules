#!/usr/bin/env bash

# Update the target system
echo -e '\n[*]\tUpdating system...'
sudo apt -qq update

# Install the required tools and dependencies on the system
echo -e '[*]\tInstalling required tools...'
sudo apt -qq install -y whois \
                        python3 \
                        python3-pip

# Ensure Python3 is upgraded if it was already installed
echo -e '[*]\tUpdating Python3...'
sudo apt -qq --only-upgrade install -y python3

# Perform clean up
echo -e '[*]\tPerforming clean up...'
sudo apt -qq -y autoremove
sudo apt -qq -y clean
sudo rm -rf /var/lib/apt/lists/*

# Now install Python dependencies
echo -e '[*]\tInstalling Python dependencies...'
pip3 install --quiet --no-cache-dir -r requirements.txt

# If we are on the system running Apache, let's enable mod_rewrite
if dpkg --get-selections | grep '^apache2\s.*install'; then
    echo -e '[*]\tEnabling mod_rewrite for Apache...'
    sudo a2enmod rewrite
fi

echo -e '\n[+]\tSet up complete for redirect.rules'