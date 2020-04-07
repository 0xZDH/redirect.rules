#!/usr/bin/env python3

import re
import requests
import dns.resolver
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Import static data
from core.support import REWRITE

# Import parent class
from core.base import Base


class GoogleCloud(Base):
    """
    Add GoogleCloud IPs: dig txt _cloud-netblocks.googleusercontent.com

    :param workingfile: Open file object where rules are written
    :param ip_list:     List of seen IPs
    """

    def __init__(self, workingfile, ip_list):
        self.workingfile = workingfile
        self.ip_list     = ip_list
        self.resolver    = dns.resolver.Resolver()

        self.return_data = self._process_source()


    def _get_source(self):
        # Write comments to working file
        print("[*]\tPulling Google Cloud IP/network list...")
        self.workingfile.write("\n\n\t# Live copy of GoogleCloud IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

        # Create our own resolver to force a DNS server in case routing
        # defaults cause an issue
        # https://stackoverflow.com/a/5237068
        self.resolver.nameservers = ['8.8.8.8']
        google_netblocks = self.resolver.query('_cloud-netblocks.googleusercontent.com', 'txt')
        # https://stackoverflow.com/a/11706378
        google_netblocks = google_netblocks.response.answer[0][-1].strings[0].decode('utf-8')

        return google_netblocks


    def _process_source(self):
        # Get the source data
        google_netblocks = self._get_source()

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
            netblock_ips = self.resolver.query(netblock, 'txt')
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
                    if ip not in self.ip_list and ip != '':
                        self.workingfile.write(REWRITE['COND_IP'].format(IP=ip))
                        self.ip_list.append(ip)  # Keep track of all things added
                        count += 1

        self.workingfile.write("\t# GoogleCloud IP Count: %d\n" % count)

        # Ensure there are conditions to catch
        if count > 0:
            # Add rewrite rule... I think this should help performance
            self.workingfile.write("\n\t# Add RewriteRule for performance\n")
            self.workingfile.write(REWRITE['END_COND'])
            self.workingfile.write(REWRITE['RULE'])

        return self.ip_list