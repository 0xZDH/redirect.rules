#!/usr/bin/env python3

import re
import requests
import dns.resolver
from datetime import datetime

# Import static data
from core.support import REWRITE

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


#> ----------------------------------------------------------------------------
# Add Tor exit nodes: https://check.torproject.org/exit-addresses
def write_tor_nodes(headers, timeout, workingfile, ip_list):
    print("[*]\tPulling TOR exit node list...")
    workingfile.write("\n\n\t# Live copy of current TOR exit nodes: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

    # Fetch the live Tor exit node list
    tor_ips = requests.get(
        'https://check.torproject.org/exit-addresses',
        headers=headers,
        timeout=timeout,
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
            if ip not in ip_list:
                workingfile.write(REWRITE['COND_IP'].format(IP=ip))
                ip_list.append(ip)  # Keep track of all things added
                count += 1

    workingfile.write("\t# Tor Exit Node Count: %d\n" % count)

    # Ensure there are conditions to catch
    if count > 0:
        # Add rewrite rule... I think this should help performance
        workingfile.write("\n\t# Add RewriteRule for performance\n")
        workingfile.write(REWRITE['END_COND'])
        workingfile.write(REWRITE['RULE'])

    return ip_list


#> ----------------------------------------------------------------------------
# Add AWS IPs: https://ip-ranges.amazonaws.com/ip-ranges.json
def write_aws(headers, timeout, workingfile, ip_list):
    print("[*]\tPulling AWS IP/Network list...")
    workingfile.write("\n\n\t# Live copy of AWS IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

    aws_ips = requests.get(
        'https://ip-ranges.amazonaws.com/ip-ranges.json',
        headers=headers,
        timeout=timeout,
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
        if ip not in ip_list:
            workingfile.write(REWRITE['COND_IP'].format(IP=ip))
            ip_list.append(ip)  # Keep track of all things added
            count += 1

    workingfile.write("\t# AWS IP Count: %d\n" % count)

    # Ensure there are conditions to catch
    if count > 0:
        # Add rewrite rule... I think this should help performance
        workingfile.write("\n\t# Add RewriteRule for performance\n")
        workingfile.write(REWRITE['END_COND'])
        workingfile.write(REWRITE['RULE'])

    return ip_list


#> ----------------------------------------------------------------------------
# Add GoogleCloud IPs: dig txt _cloud-netblocks.googleusercontent.com
def write_google_cloud(workingfile, ip_list):
    print("[*]\tPulling Google Cloud IP/network list...")
    workingfile.write("\n\n\t# Live copy of GoogleCloud IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

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
                if ip not in ip_list:
                    workingfile.write(REWRITE['COND_IP'].format(IP=ip))
                    ip_list.append(ip)  # Keep track of all things added
                    count += 1

    workingfile.write("\t# GoogleCloud IP Count: %d\n" % count)

    # Ensure there are conditions to catch
    if count > 0:
        # Add rewrite rule... I think this should help performance
        workingfile.write("\n\t# Add RewriteRule for performance\n")
        workingfile.write(REWRITE['END_COND'])
        workingfile.write(REWRITE['RULE'])

    return ip_list


#> -----------------------------------------------------------------------------
# Add Microsoft Azure IPs: https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653
def write_azure(headers, timeout, workingfile, ip_list):
    print("[*]\tPulling Microsoft Azure IP/network list...")
    workingfile.write("\n\n\t# Live copy of Microsoft Azure IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

    # Go to download page
    ms_download_page = requests.get(
        'https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653',
        headers=headers,
        timeout=timeout,
        verify=False
    ).content.decode('utf-8').split('\n')

    # Grab download link
    for line in ms_download_page:
        if 'click here' in line:
            link = re.search('href="(.+?)"', line.strip()).group(1)

    # Download IP list
    azure_subnets = requests.get(
        link,
        headers=headers,
        timeout=timeout,
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
            if ip not in ip_list:
                workingfile.write(REWRITE['COND_IP'].format(IP=ip))
                ip_list.append(ip)  # Keep track of all things added
                count += 1

    workingfile.write("\t# Microsoft Azure IP Count: %d\n" % count)

    # Ensure there are conditions to catch
    if count > 0:
        # Add rewrite rule... I think this should help performance
        workingfile.write("\n\t# Add RewriteRule for performance\n")
        workingfile.write(REWRITE['END_COND'])
        workingfile.write(REWRITE['RULE'])

    return ip_list


#> -----------------------------------------------------------------------------
# Add Office365 IPs: https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7
# https://rhinosecuritylabs.com/social-engineering/bypassing-email-security-url-scanning/
def write_office_365(headers, timeout, workingfile, ip_list, host_list):
    print("[*]\tPulling Office 365 IP list...")
    workingfile.write("\n\n\t# Adding Office 365 IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

    o365_networks = requests.get(
        'https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7',
        headers=headers,
        timeout=timeout,
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
            workingfile.write("\t# %s\n" % network['serviceAreaDisplayName'])
            # If we have URLs, lets document them
            if 'urls' in network.keys():
                for url in network['urls']:
                    url = '^%s$' % url  # Add regex style to host

                    if url not in host_list:
                        workingfile.write(REWRITE['COND_HOST'].format(HOSTNAME=url))
                        host_list.append(url)
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
                        if ip not in ip_list:
                            workingfile.write(REWRITE['COND_IP'].format(IP=ip))
                            ip_list.append(ip)  # Keep track of all things added
                            count_ip += 1

    workingfile.write("\t# Office 365 Host Count: %d\n" % count_host)
    workingfile.write("\t# Office 365 IP Count:   %d\n" % count_ip)

    # Ensure there are conditions to catch
    if count_ip > 0 or count_host > 0:
        # Add rewrite rule... I think this should help performance
        workingfile.write("\n\t# Add RewriteRule for performance\n")
        workingfile.write(REWRITE['END_COND'])
        workingfile.write(REWRITE['RULE'])

    return (ip_list, host_list)


#> -----------------------------------------------------------------------------
# Add Oracle Cloud IPs: https://docs.cloud.oracle.com/en-us/iaas/tools/public_ip_ranges.json
def write_oracle_cloud(headers, timeout, workingfile, ip_list):
    print("[*]\tPulling Oracle Cloud IP list...")
    workingfile.write("\n\n\t# Adding Oracle Cloud IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

    oracle_networks = requests.get(
        'https://docs.cloud.oracle.com/en-us/iaas/tools/public_ip_ranges.json',
        headers=headers,
        timeout=timeout,
        verify=False
    ).json()

    count = 0
    for region in oracle_networks['regions']:
        workingfile.write("\n\t# Oracle Cloud Region: %s\n" % region['region'])
        for cidr in region['cidrs']:
            ip = cidr['cidr']
            # Convert /31 and /32 CIDRs to single IP
            ip = re.sub('/3[12]', '', ip)

            # Convert lower-bound CIDRs into /24 by default
            # This is assmuming that if a portion of the net
            # was seen, we want to avoid the full netblock
            ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)

            # Check if the current IP/CIDR has been seen
            if ip not in ip_list:
                workingfile.write(REWRITE['COND_IP'].format(IP=ip))
                ip_list.append(ip)  # Keep track of all things added
                count += 1

    workingfile.write("\t# Oracle Cloud IP Count:   %d\n" % count)

    # Ensure there are conditions to catch
    if count > 0:
        # Add rewrite rule... I think this should help performance
        workingfile.write("\n\t# Add RewriteRule for performance\n")
        workingfile.write(REWRITE['END_COND'])
        workingfile.write(REWRITE['RULE'])

    return ip_list