#!/usr/bin/env python3

#> -----------------------------------------------------------------------------

#   Quick and dirty dynamic redirect.rules generator

#   This is a Python rewrite and expansion of:
#    - https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
#    - https://github.com/violentlydave/mkhtaccess_red/blob/master/mkhtaccess_red

#   The current state of this script is pretty messy. There is a lot of replicated
#   code that can be cleaned up at some point. This was written in this way when
#   the base logic was ported to Python from bash.

#> -----------------------------------------------------------------------------

import os
import re
import sys
import json
import time
import socket
import requests
import subprocess
import dns.resolver
from datetime import datetime

# Import data objects from data/ dir
from data import ips, asns, misc, agents, hostnames

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Exit the script if not run on *nix based system
if os.name != 'posix':
    print('[!]\tScript must be run on a *nix based machine.')
    sys.exit()

# Exit the script if no destination provided
if len(sys.argv) < 2:
    print('[!]\tMissing redirect destination parameter.')
    print('[+]\tusage: %s [REDIRECT_DOMAIN]' % __file__)
    sys.exit()


# =================
#   CONFIGURATION
# =================

__version__ = '1.1'

## Start timer
start = time.perf_counter()

## Global files
LOGFILE_NAME     = '/tmp/redirect_logfile'
WORKINGFILE_NAME = '/tmp/redirect.rules'
LOGFILE     = open(LOGFILE_NAME, 'w')
WORKINGFILE = open(WORKINGFILE_NAME, 'w')

## Redirect destination
DESTINATION = sys.argv[1]

## HTTP requests config
TIMEOUT = 10
HTTP_HEADERS = {
    'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:74.0) Gecko/20100101 Firefox/74.0"
}

## Static data objects from data/ dir
# The majority of the static data came from @curi0usJack and
# @violentlydave, but was expanded on further

# User-Agents Lists
#   -- @curi0usJack and @violentlydave
#   -- Malware Kit
AGENTS = {
    '@curi0usJack/@violentlydave': agents.jack_agents,
    'Obtained via Malware Kit': agents.malware_kit_agents
}

# Individual Company ASNs
#   -- @curi0usJack and @violentlydave
#   :Format: CompanyName_AS12345
ASNS = asns.asns

# Misc sources (seen in phishing attempts/etc.)
#   -- @curi0usJack and @violentlydave
#   :Format: ipORnetwork-Ownername-Reason
MISC = misc.misc

# IPs and Hostnames obtained via MalwareKit
MK_IPS = ips.malware_kit_ips
MK_HOSTNAMES = hostnames.malware_kit_hostnames

## De-dupe data storage
full_ip_list    = []  # De-dupe ips
full_host_list  = []  # De-dupe hosts
full_agent_list = []  # De-dupe agents

## RewriteEngine rewrite rules and conditions
REWRITE_COND_IP    = '\tRewriteCond\t\t\t\texpr\t\t\t\t\t"-R \'{IP}\'"\t[OR]\n'
REWRITE_COND_HOST  = '\tRewriteCond\t\t\t\t%{{HTTP_HOST}}\t\t\t\t\t{HOSTNAME}\t[OR,NC]\n'
REWRITE_COND_AGENT = '\tRewriteCond\t\t\t\t%{{HTTP_USER_AGENT}}\t\t\t\t\t{AGENT}\t[OR,NC]\n'
REWRITE_END_COND   = '\tRewriteCond\t\t\t\texpr\t\t\t\t\t"-R \'192.168.250.250\'"\n'
REWRITE_RULE       = '\tRewriteRule\t\t\t\t^.*$\t\t\t\t\t%{REQUEST_SCHEME}://${REDIR_TARGET}\t[L,R=302]\n'

## Banner
print('''
----------------------------------
  Redirect Rules Generation Tool
               v{VERS}
----------------------------------
'''.format(VERS=__version__))



#> ----------------------------------------------------------------------------
# Initialize redirect.rules file
# Add comments/author to the redirect.rules file headers
WORKINGFILE.write("\t#\n")
WORKINGFILE.write("\t# %s to block AV Sandboxes - started: %s\n" % (__file__, datetime.now().strftime("%Y%m%d-%H:%M:%S")))
WORKINGFILE.write("\t#\n\n")


#> -----------------------------------------------------------------------------
# Grab @curi0usJack's .htaccess rules: https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
# Primary data source
# Current raw link as of: March 27, 2020
print("[*]\tPulling @curi0usJack's redirect rules...")
curious_jack_file = requests.get(
    'https://gist.githubusercontent.com/curi0usJack/971385e8334e189d93a6cb4671238b10/raw/13b11edf67f746bdd940ff3f2e9b8dc18f8ad7d4/.htaccess',
    headers=HTTP_HEADERS,
    timeout=TIMEOUT,
    verify=False
).content.decode('utf-8').split('\n')

# Write the file contents to our local redirect.rules, but remove
# TODO at top of file. Also, add all rewrite conditions to a list
# so we can de-dupe later on
print("[*]\tWriting @curi0usJack's redirect rules...")

# Keep count of the IP/User-Agents currently documented
count_ip = 0
count_ua = 0

line_num = 0
for line in curious_jack_file:

    # Remove if the TODO is dropped from the .htaccess file
    if line_num > 2:

        # Add user-supplied redirect destination
        if 'DESTINATIONURL' in line:
            line = re.sub('\|DESTINATIONURL\|', DESTINATION, line)

        WORKINGFILE.write(line + '\n')  # Add new-line since we split data before

        # Check for IPs to keep a list for de-duping
        if all(x in line for x in ['RewriteCond', 'expr']):
            full_ip_list.append(line.split("'")[1])
            count_ip += 1

        # Check for User-Agents to keep a list for de-duping
        if all(x in line for x in ['RewriteCond', 'HTTP_USER_AGENT']):
            if '"' in line:  # This is specific to one of the user-agents
                full_agent_list.append(re.search('"(.+)"', line).group(1))

            else:
                full_agent_list.append(re.search('(\^.+\$)', line).group(1))

            count_ua += 1

    else:
        # We only care about this for the first few iterations
        line_num += 1

WORKINGFILE.write("\t# @curi0usJack IP Count:         %d\n" % count_ip)
WORKINGFILE.write("\t# @curi0usJack User Agent Count: %d\n" % count_ua)


#> -----------------------------------------------------------------------------
# Add custom User-Agent list
print("[*]\tAdding conditions for bad User-Agents...")
WORKINGFILE.write("\n\n\t# Bad User Agents: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

count = 0
for source in AGENTS.keys():
    WORKINGFILE.write("\n\t# Source: %s\n" % source)
    for agent in AGENTS[source]:
        if agent not in full_agent_list:
            WORKINGFILE.write(REWRITE_COND_AGENT.format(AGENT=agent))
            full_agent_list.append(agent)  # Keep track of all things added
            count += 1

WORKINGFILE.write("\t# Bad User Agent Count: %d\n" % count)

# Ensure there are conditions to catch
if count > 0:
    # Add rewrite rule... I think this should help performance
    WORKINGFILE.write("\n\t# Add RewriteRule for performance\n")
    WORKINGFILE.write(REWRITE_END_COND)
    WORKINGFILE.write(REWRITE_RULE)


#> -----------------------------------------------------------------------------
# Add hostnames and IPs obtained via Malware Kit
print("[*]\tAdding Hostnames and IPs obtained via Malware Kit...")
WORKINGFILE.write("\n\n\t# Hostnames/IPs obtained via Malware Kit: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

WORKINGFILE.write("\n\t# Hostnames\n")
count = 0
for host in MK_HOSTNAMES:
    if host not in full_host_list:
        WORKINGFILE.write(REWRITE_COND_HOST.format(HOSTNAME=host))
        full_host_list.append(host)  # Keep track of all things added
        count += 1

WORKINGFILE.write("\t# Hostname Count: %d\n" % count)

WORKINGFILE.write("\n\t# IPs\n")
count = 0
for ip in MK_IPS:
    # Convert /31 and /32 CIDRs to single IP
    ip = re.sub('/3[12]', '', ip)

    # Convert lower-bound CIDRs into /24 by default
    # This is assmuming that if a portion of the net
    # was seen, we want to avoid the full netblock
    ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)

    # Check if the current IP/CIDR has been seen
    if ip not in full_ip_list:
        WORKINGFILE.write(REWRITE_COND_IP.format(IP=ip))
        full_ip_list.append(ip)  # Keep track of all things added
        count += 1

WORKINGFILE.write("\t# IP Count: %d\n" % count)

# Ensure there are conditions to catch
if count > 0:
    # Add rewrite rule... I think this should help performance
    WORKINGFILE.write("\n\t# Add RewriteRule for performance\n")
    WORKINGFILE.write(REWRITE_END_COND)
    WORKINGFILE.write(REWRITE_RULE)


#> -----------------------------------------------------------------------------
# Add Tor exit nodes: https://check.torproject.org/exit-addresses
print("[*]\tPulling TOR exit node list...")
WORKINGFILE.write("\n\n\t# Live copy of current TOR exit nodes: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

# Fetch the live Tor exit node list
tor_ips = requests.get(
    'https://check.torproject.org/exit-addresses',
    headers=HTTP_HEADERS,
    timeout=TIMEOUT,
    verify=False
).content.decode('utf-8').split('\n')

count = 0
for line in tor_ips:
    line = line.strip()
    if 'ExitAddress' in line:
        ip = line.split(' ')[1]
        # Convert /31 and /32 CIDRs to single IP
        ip = re.sub('/3[12]', '', ip)

        # Convert lower-bound CIDRs into /24 by default
        # This is assmuming that if a portion of the net
        # was seen, we want to avoid the full netblock
        ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)

        # Check if the current IP/CIDR has been seen
        if ip not in full_ip_list:
            WORKINGFILE.write(REWRITE_COND_IP.format(IP=ip))
            full_ip_list.append(ip)  # Keep track of all things added
            count += 1

WORKINGFILE.write("\t# Tor Exit Node Count: %d\n" % count)

# Ensure there are conditions to catch
if count > 0:
    # Add rewrite rule... I think this should help performance
    WORKINGFILE.write("\n\t# Add RewriteRule for performance\n")
    WORKINGFILE.write(REWRITE_END_COND)
    WORKINGFILE.write(REWRITE_RULE)


#> -----------------------------------------------------------------------------
# Add AWS IPs: https://ip-ranges.amazonaws.com/ip-ranges.json
print("[*]\tPulling AWS IP/Network list...")
WORKINGFILE.write("\n\n\t# Live copy of AWS IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

aws_ips = requests.get(
    'https://ip-ranges.amazonaws.com/ip-ranges.json',
    headers=HTTP_HEADERS,
    timeout=TIMEOUT,
    verify=False
).json()

count = 0
for network in aws_ips['prefixes']:
    ip = network['ip_prefix']
    # Convert /31 and /32 CIDRs to single IP
    ip = re.sub('/3[12]', '', ip)

    # Convert lower-bound CIDRs into /24 by default
    # This is assmuming that if a portion of the net
    # was seen, we want to avoid the full netblock
    ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)

    # Check if the current IP/CIDR has been seen
    if ip not in full_ip_list:
        WORKINGFILE.write(REWRITE_COND_IP.format(IP=ip))
        full_ip_list.append(ip)  # Keep track of all things added
        count += 1

WORKINGFILE.write("\t# AWS IP Count: %d\n" % count)

# Ensure there are conditions to catch
if count > 0:
    # Add rewrite rule... I think this should help performance
    WORKINGFILE.write("\n\t# Add RewriteRule for performance\n")
    WORKINGFILE.write(REWRITE_END_COND)
    WORKINGFILE.write(REWRITE_RULE)


#> -----------------------------------------------------------------------------
# Add GoogleCloud IPs: dig txt _cloud-netblocks.googleusercontent.com
print("[*]\tPulling Google Cloud IP/network list...")
WORKINGFILE.write("\n\n\t# Live copy of GoogleCloud IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

# Create our own resolver to force a DNS server in case routing
# defaults cause an issue
# https://stackoverflow.com/a/5237068
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8']
google_netblocks = resolver.query('_cloud-netblocks.googleusercontent.com', 'txt')
# https://stackoverflow.com/a/11706378
google_netblocks = google_netblocks.response.answer[0][-1].strings[0].decode('utf-8')

netblocks = []
# Now split up the Answer
for netblock in google_netblocks.split(' '):
    # Grab only the includes
    if 'include' in netblock:
        # Split the netblock from 'include'
        netblocks.append(netblock.split(':')[-1])

count = 0
for netblock in netblocks:
    # Query each GoogleCloud netblock
    netblock_ips = resolver.query(netblock, 'txt')
    netblock_ips = netblock_ips.response.answer[0][-1].strings[0].decode('utf-8')
    # Loop over the Answer for IPv4 CIDRs
    for netblock_ip in netblock_ips.split(' '):
        if 'ip4' in netblock_ip:
            ip = netblock_ip.split(':')[-1]
            # Convert /31 and /32 CIDRs to single IP
            ip = re.sub('/3[12]', '', ip)

            # Convert lower-bound CIDRs into /24 by default
            # This is assmuming that if a portion of the net
            # was seen, we want to avoid the full netblock
            ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)

            # Check if the current IP/CIDR has been seen
            if ip not in full_ip_list:
                WORKINGFILE.write(REWRITE_COND_IP.format(IP=ip))
                full_ip_list.append(ip)  # Keep track of all things added
                count += 1

WORKINGFILE.write("\t# GoogleCloud IP Count: %d\n" % count)

# Ensure there are conditions to catch
if count > 0:
    # Add rewrite rule... I think this should help performance
    WORKINGFILE.write("\n\t# Add RewriteRule for performance\n")
    WORKINGFILE.write(REWRITE_END_COND)
    WORKINGFILE.write(REWRITE_RULE)


#> -----------------------------------------------------------------------------
# Add Microsoft Azure IPs: https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653
print("[*]\tPulling Microsoft Azure IP/network list...")
WORKINGFILE.write("\n\n\t# Live copy of Microsoft Azure IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

# Go to download page
ms_download_page = requests.get(
    'https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653',
    headers=HTTP_HEADERS,
    timeout=TIMEOUT,
    verify=False
).content.decode('utf-8').split('\n')

# Grab download link
for line in ms_download_page:
    if 'click here' in line:
        link = re.search('href="(.+?)"', line.strip()).group(1)

# Download IP list
azure_subnets = requests.get(
    link,
    headers=HTTP_HEADERS,
    timeout=TIMEOUT,
    verify=False
).content.decode('utf-8').split('\n')

count = 0
for subnet in azure_subnets:
    if 'IpRange Subnet' in subnet:
        ip = re.search('"(.+?)"', subnet.strip()).group(1)
        # Convert /31 and /32 CIDRs to single IP
        ip = re.sub('/3[12]', '', ip)

        # Convert lower-bound CIDRs into /24 by default
        # This is assmuming that if a portion of the net
        # was seen, we want to avoid the full netblock
        ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)

        # Check if the current IP/CIDR has been seen
        if ip not in full_ip_list:
            WORKINGFILE.write(REWRITE_COND_IP.format(IP=ip))
            full_ip_list.append(ip)  # Keep track of all things added
            count += 1

WORKINGFILE.write("\t# Microsoft Azure IP Count: %d\n" % count)

# Ensure there are conditions to catch
if count > 0:
    # Add rewrite rule... I think this should help performance
    WORKINGFILE.write("\n\t# Add RewriteRule for performance\n")
    WORKINGFILE.write(REWRITE_END_COND)
    WORKINGFILE.write(REWRITE_RULE)


#> -----------------------------------------------------------------------------
# Add Office365 IPs: https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7
# https://rhinosecuritylabs.com/social-engineering/bypassing-email-security-url-scanning/
print("[*]\tPulling Office 365 IP list...")
WORKINGFILE.write("\n\n\t# Adding Office 365 IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

o365_networks = requests.get(
    'https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7',
    headers=HTTP_HEADERS,
    timeout=TIMEOUT,
    verify=False
).json()

# Since this returns a JSON object with both URLs and IPs,
# lets handle accordingly
# This is going to be messy since we are going to attempt to
# note each service
o365_ips  = []
o365_urls = []

# Loop over the JSON objects
# This is gross...
count_ip   = 0
count_host = 0
for network in o365_networks:
    # Make sure we have IPs/URLs to handle
    if any(x in network.keys() for x in ['ips', 'urls']):
        WORKINGFILE.write("\t# %s\n" % network['serviceAreaDisplayName'])
        # If we have URLs, lets document them
        if 'urls' in network.keys():
            for url in network['urls']:
                url = '^%s$' % url  # Add regex style to host

                if url not in full_host_list:
                    WORKINGFILE.write(REWRITE_COND_HOST.format(HOSTNAME=url))
                    full_host_list.append(url)
                    count_host += 1

        # If we have IPs, lets document them
        if 'ips' in network.keys():
            for ip in network['ips']:
                if ':' not in ip:  # Ignore v6
                    # Convert /31 and /32 CIDRs to single IP
                    ip = re.sub('/3[12]', '', ip)

                    # Convert lower-bound CIDRs into /24 by default
                    # This is assmuming that if a portion of the net
                    # was seen, we want to avoid the full netblock
                    ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)

                    # Check if the current IP/CIDR has been seen
                    if ip not in full_ip_list:
                        WORKINGFILE.write(REWRITE_COND_IP.format(IP=ip))
                        full_ip_list.append(ip)  # Keep track of all things added
                        count_ip += 1

WORKINGFILE.write("\t# Office 365 Host Count: %d\n" % count_host)
WORKINGFILE.write("\t# Office 365 IP Count:   %d\n" % count_ip)

# Ensure there are conditions to catch
if count_ip > 0 or count_host > 0:
    # Add rewrite rule... I think this should help performance
    WORKINGFILE.write("\n\t# Add RewriteRule for performance\n")
    WORKINGFILE.write(REWRITE_END_COND)
    WORKINGFILE.write(REWRITE_RULE)


#> -----------------------------------------------------------------------------
# Add Oracle Cloud IPs: https://docs.cloud.oracle.com/en-us/iaas/tools/public_ip_ranges.json
print("[*]\tPulling Oracle Cloud IP list...")
WORKINGFILE.write("\n\n\t# Adding Oracle Cloud IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

oracle_networks = requests.get(
    'https://docs.cloud.oracle.com/en-us/iaas/tools/public_ip_ranges.json',
    headers=HTTP_HEADERS,
    timeout=TIMEOUT,
    verify=False
).json()

count = 0
for region in oracle_networks['regions']:
    WORKINGFILE.write("\n\t# Oracle Cloud Region: %s\n" % region['region'])
    for cidr in region['cidrs']:
        ip = cidr['cidr']
        # Convert /31 and /32 CIDRs to single IP
        ip = re.sub('/3[12]', '', ip)

        # Convert lower-bound CIDRs into /24 by default
        # This is assmuming that if a portion of the net
        # was seen, we want to avoid the full netblock
        ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)

        # Check if the current IP/CIDR has been seen
        if ip not in full_ip_list:
            WORKINGFILE.write(REWRITE_COND_IP.format(IP=ip))
            full_ip_list.append(ip)  # Keep track of all things added
            count += 1

WORKINGFILE.write("\t# Oracle Cloud IP Count:   %d\n" % count)

# Ensure there are conditions to catch
if count > 0:
    # Add rewrite rule... I think this should help performance
    WORKINGFILE.write("\n\t# Add RewriteRule for performance\n")
    WORKINGFILE.write(REWRITE_END_COND)
    WORKINGFILE.write(REWRITE_RULE)


#> -----------------------------------------------------------------------------
# Add companies by ASN - via whois.radb.net
for asn in ASNS:
    asn = asn.split('_')
    print("[*]\tPulling %s -- %s via RADB..." % (asn[1], asn[0]))
    WORKINGFILE.write("\n\n\t# Live copy of %s ips based on RADB ASN %s: %s\n" % (
        asn[0],
        asn[1],
        datetime.now().strftime("%Y%m%d-%H:%M:%S")
    ))

    # Unfortunately here, it seems we must use subprocess as some
    # whois libraries were acting funky...
    whois_cmd  = 'whois -h whois.radb.net -- -i origin %s | grep "route:" | awk \'{print $2}\'' % (asn[1])
    whois_data = subprocess.check_output(whois_cmd, shell=True).decode('utf-8')

    count = 0
    for ip in whois_data.split('\n'):
        # Convert /31 and /32 CIDRs to single IP
        ip = re.sub('/3[12]', '', ip)

        # Convert lower-bound CIDRs into /24 by default
        # This is assmuming that if a portion of the net
        # was seen, we want to avoid the full netblock
        ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)

        # Check if the current IP/CIDR has been seen
        if ip not in full_ip_list:
            WORKINGFILE.write(REWRITE_COND_IP.format(IP=ip))
            full_ip_list.append(ip)  # Keep track of all things added
            count += 1

    WORKINGFILE.write("\t# %s - %s Count: %d\n" % (asn[0], asn[1], count))

    # Ensure there are conditions to catch
    if count > 0:
        # Add rewrite rule... I think this should help performance
        WORKINGFILE.write("\n\t# Add RewriteRule for performance\n")
        WORKINGFILE.write(REWRITE_END_COND)
        WORKINGFILE.write(REWRITE_RULE)


#> -----------------------------------------------------------------------------
# Add companies by ASN - via BGPView
for asn in ASNS:
    asn = asn.split('_')
    print("[*]\tPulling %s -- %s via BGPView..." % (asn[1], asn[0]))
    WORKINGFILE.write("\n\n\t# Live copy of %s ips based on BGPView ASN %s: %s\n" % (
        asn[0],
        asn[1],
        datetime.now().strftime("%Y%m%d-%H:%M:%S")
    ))

    asn_data = requests.get(
        'https://api.bgpview.io/asn/%s/prefixes' % asn[1],
        headers=HTTP_HEADERS,
        timeout=TIMEOUT,
        verify=False
    ).json()

    try:
        count = 0
        for network in asn_data['data']['ipv4_prefixes']:
            ip = network['prefix']
            # Convert /31 and /32 CIDRs to single IP
            ip = re.sub('/3[12]', '', ip)

            # Convert lower-bound CIDRs into /24 by default
            # This is assmuming that if a portion of the net
            # was seen, we want to avoid the full netblock
            ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)

            # Check if the current IP/CIDR has been seen
            if ip not in full_ip_list:
                WORKINGFILE.write(REWRITE_COND_IP.format(IP=ip))
                full_ip_list.append(ip)  # Keep track of all things added
                count += 1

    except KeyError:
        pass

    WORKINGFILE.write("\t# %s - %s Count: %d\n" % (asn[0], asn[1], count))

    # Ensure there are conditions to catch
    if count > 0:
        # Add rewrite rule... I think this should help performance
        WORKINGFILE.write("\n\t# Add RewriteRule for performance\n")
        WORKINGFILE.write(REWRITE_END_COND)
        WORKINGFILE.write(REWRITE_RULE)


#> -----------------------------------------------------------------------------
# Misc sources -- see data/misc.py for reasons
print("[*]\tAdding Misc Sources")
WORKINGFILE.write("\n\n\t# Misc Sources: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

count = 0
for obj in MISC:
    obj = obj.split('-')
    ip  = obj[0]
    # Convert /31 and /32 CIDRs to single IP
    ip = re.sub('/3[12]', '', ip)

    # Convert lower-bound CIDRs into /24 by default
    # This is assmuming that if a portion of the net
    # was seen, we want to avoid the full netblock
    ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)

    # Check if the current IP/CIDR has been seen
    if ip not in full_ip_list:
        WORKINGFILE.write(REWRITE_COND_IP.format(IP=ip))
        full_ip_list.append(ip)  # Keep track of all things added
        count += 1

WORKINGFILE.write("\t# Misc IP Count: %d\n" % count)

# Ensure there are conditions to catch
if count > 0:
    # Add rewrite rule... I think this should help performance
    WORKINGFILE.write("\n\t# Add RewriteRule for performance\n")
    WORKINGFILE.write(REWRITE_END_COND)
    WORKINGFILE.write(REWRITE_RULE)


#> -----------------------------------------------------------------------------
# Rule clean up
print("\n[*]\tPerforming rule de-duplication clean up...")
WORKINGFILE.close()  # Close out working file before modding it

# Let's build our CIDR map to identify redundant CIDRs
tmp_ip_list   = []
tmp_cidr_list = {}
for ip in full_ip_list:
    if '/' in ip:  # Make sure its a CIDR
        ip = ip.split('/')
        if ip[0] not in tmp_cidr_list.keys():
            tmp_cidr_list[ip[0]] = []
        tmp_cidr_list[ip[0]].append(int(ip[1]))
    else:
        tmp_ip_list.append(ip)

# Let's build our remove list
remove_list = []

# Add CIDRs to remove
for net in tmp_cidr_list.keys():
    if len(tmp_cidr_list[net]) > 1:
        min_cidr = min(tmp_cidr_list[net])
        for cidr in tmp_cidr_list[net]:
            if cidr != min_cidr:
                net = re.sub('\.', '\\.', net)
                remove_list.append(net + '\\/' + str(cidr))

# Add IPs to remove
for ip in tmp_ip_list:
    ip_cidr = re.sub('\.[0-9]{1,3}$', '.0/24', ip)
    if ip_cidr in full_ip_list:
        ip = re.sub('\.', '\\.', ip)
        remove_list.append(ip)

print("[*]\tRemoving %d duplicate IPs/Networks..." % len(remove_list))
# Now let's comment out each CIDR
# Clean remove list first (this was an issue at one point)
remove_list = [x for x in remove_list if x.strip() != '']
for cidr in remove_list:
    command = "sed -e '/%s/ s/^#*/#/' -i %s" % (cidr, WORKINGFILE_NAME)
    result  = subprocess.check_output(command, shell=True)

# Use a little more bash for counting conditions created
command = 'grep -c "RewriteCond" %s | grep -v "#"' % WORKINGFILE_NAME
result  = subprocess.check_output(command, shell=True).decode('utf-8')
result  = int(result.strip())
print("\n[*]\tTotal IPs, Networks or User-Agents blocked: %d" % result)
print("[*]\tRedirect rules file: %s" % WORKINGFILE_NAME)


elapsed = time.perf_counter() - start
print(f"\n{__file__} executed in {elapsed:0.2f} seconds.")