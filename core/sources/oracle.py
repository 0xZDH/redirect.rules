#!/usr/bin/env python3

import re
import requests
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Import static data
from core.support import REWRITE

# Import parent class
from core.base import Base


class OracleCloud(Base):
    """
    Add Oracle Cloud IPs: https://docs.cloud.oracle.com/en-us/iaas/tools/public_ip_ranges.json

    :param workingfile: Open file object where rules are written
    :param headers:     HTTP headers
    :param timeout:     HTTP timeout
    :param ip_list:     List of seen IPs
    """

    def __init__(self, workingfile, headers, timeout, ip_list):
        self.workingfile = workingfile
        self.headers     = headers
        self.timeout     = timeout
        self.ip_list     = ip_list

        self.return_data = self._process_source()


    def _get_source(self):
        # Write comments to working file
        print("[*]\tPulling Oracle Cloud IP/network list...")
        self.workingfile.write("\n\n\t# Adding Oracle Cloud IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

        oracle_networks = requests.get(
            'https://docs.cloud.oracle.com/en-us/iaas/tools/public_ip_ranges.json',
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        )

        # Return JSON object
        return oracle_networks.json()


    def _process_source(self):
        try:
            # Get the source data
            oracle_networks = self._get_source()
        except:
            return self.ip_list

        count = 0
        for region in oracle_networks['regions']:
            self.workingfile.write("\n\t# Oracle Cloud Region: %s\n" % region['region'])
            for cidr in region['cidrs']:
                ip = cidr['cidr']
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

        self.workingfile.write("\t# Oracle Cloud IP Count:   %d\n" % count)

        # Ensure there are conditions to catch
        if count > 0:
            # Add rewrite rule... I think this should help performance
            self.workingfile.write("\n\t# Add RewriteRule for performance\n")
            self.workingfile.write(REWRITE['END_COND'])
            self.workingfile.write(REWRITE['RULE'])

        return self.ip_list