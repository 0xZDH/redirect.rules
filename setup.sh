#!/usr/bin/env bash

#
#   This script automates the setup process for redirect.rules and
#   automatically installs any and all modules and tools. Once the
#   environment is built, run the redirect.rules tool:
#           python3 redirect_rules.py -d test.com
# 
#   Follow the instructions within the /tmp/redirect.rules file
#   for use with Apache2
#


# Make sure we are running this script as root
if [[ $EUID -ne 0 ]]; then
   echo -e '[!]\tThis script must be run as root'
   exit 1
fi


# Update the target system
echo -e '[*]\tUpdating system'
apt-get -qq update

# Install the required tools and dependencies on the system
echo -e '[*]\tInstalling required system tools'
apt-get -qq install -y whois \
                       python3 \
                       python3-pip

# Ensure Python3 is upgraded if it was already installed
echo -e '[*]\tUpdating Python3'
apt-get -qq --only-upgrade install -y python3

# Perform clean up
echo -e '[*]\tPerforming system clean up'
apt-get -qq -y autoremove
apt-get -qq -y clean
rm -rf /var/lib/apt/lists/*

# Now install Python dependencies
echo -e '[*]\tInstalling Python dependencies'
pip3 install --quiet --no-cache-dir -r requirements.txt

# If we are on the system running Apache, let's enable mod_rewrite
if dpkg --get-selections | grep '^apache2\s.*install'; then
    echo -e '[*]\tEnabling mod_rewrite for Apache'
    a2enmod rewrite
fi

echo -e '\n[+]\tSet up complete for redirect.rules'