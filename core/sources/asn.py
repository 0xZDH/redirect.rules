#!/usr/bin/env python3

import os
import re
import requests
import subprocess
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Import static data
from core.support import REWRITE

# Import parent class
from core.base import Base


class RADB(Base):
    """
    Add companies by ASN - via whois.radb.net

    :param workingfile: Open file object where rules are written
    :param ip_list:     List of seen IPs
    :param args:        Command line args
    """

    def __init__(self, workingfile, ip_list, args):
        self.workingfile = workingfile
        self.ip_list     = ip_list
        self.args        = args

        self.return_data = self._process_source()


    def _get_source(self):
        # Read in static source file from static/ dir
        asn_list = []
        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/asns.txt', 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    asn_list.append(line)

        return asn_list


    def _process_source(self):
        try:
            # Get the source data
            asn_list = self._get_source()
        except:
            return self.ip_list

        asn_list = [x.upper() for x in asn_list]

        for asn in asn_list:
            if any(x.upper() in asn for x in self.args.exclude):
                continue  # Skip ASN if excluded

            asn = asn.split('_')

            print("[*]\tPulling %s -- %s via RADB..." % (asn[1], asn[0]))
            self.workingfile.write("\n\n\t# Live copy of %s ips based on RADB ASN %s: %s\n" % (
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
                if ip not in self.ip_list and ip != '':
                    self.workingfile.write(REWRITE['COND_IP'].format(IP=ip))
                    self.ip_list.append(ip)  # Keep track of all things added
                    count += 1

            self.workingfile.write("\t# %s - %s Count: %d\n" % (asn[0], asn[1], count))

            # Ensure there are conditions to catch
            if count > 0:
                # Add rewrite rule... I think this should help performance
                self.workingfile.write("\n\t# Add RewriteRule for performance\n")
                self.workingfile.write(REWRITE['END_COND'])
                self.workingfile.write(REWRITE['RULE'])

        return self.ip_list



class BGPView(Base):
    """
    Add companies by ASN - via BGPView

    :param workingfile: Open file object where rules are written
    :param headers:     HTTP headers
    :param timeout:     HTTP timeout
    :param ip_list:     List of seen IPs
    :param args:        Command line arguments
    """

    def __init__(self, workingfile, headers, timeout, ip_list, args):
        self.workingfile = workingfile
        self.headers     = headers
        self.timeout     = timeout
        self.ip_list     = ip_list
        self.args        = args

        self.return_data = self._process_source()


    def _get_source(self):
        # Read in static source file from static/ dir
        asn_list = []
        with open('../static/asns.txt', 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    asn_list.append(line)

        return asn_list


    def _get_data(self, asn):
        asn_data = requests.get(
            'https://api.bgpview.io/asn/%s/prefixes' % asn[1],
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        )

        # Return JSON object
        return asn_data.json()


    def _process_source(self):
        try:
            # Get the source data
            asn_list = self._get_source()
        except:
            return self.ip_list

        asn_list = [x.upper() for x in asn_list]

        for asn in asn_list:
            if any(x.upper() in asn for x in self.args.exclude):
                continue  # Skip ASN if excluded

            asn = asn.split('_')

            try:
                # Get the source data
                asn_data = self._get_data(asn)
            except:
                continue

            # Write comments to working file
            print("[*]\tPulling %s -- %s via BGPView..." % (asn[1], asn[0]))
            self.workingfile.write("\n\n\t# Live copy of %s ips based on BGPView ASN %s: %s\n" % (
                asn[0],
                asn[1],
                datetime.now().strftime("%Y%m%d-%H:%M:%S")
            ))

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
                    if ip not in self.ip_list and ip != '':
                        self.workingfile.write(REWRITE['COND_IP'].format(IP=ip))
                        self.ip_list.append(ip)  # Keep track of all things added
                        count += 1

            except KeyError:
                pass

            self.workingfile.write("\t# %s - %s Count: %d\n" % (asn[0], asn[1], count))

            # Ensure there are conditions to catch
            if count > 0:
                # Add rewrite rule... I think this should help performance
                self.workingfile.write("\n\t# Add RewriteRule for performance\n")
                self.workingfile.write(REWRITE['END_COND'])
                self.workingfile.write(REWRITE['RULE'])

        return self.ip_list