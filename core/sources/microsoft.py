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


class Azure(Base):
    """
    # Add Microsoft Azure IPs: https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653

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
        print("[*]\tPulling Microsoft Azure IP/network list...")
        self.workingfile.write("\n\n\t# Live copy of Microsoft Azure IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

        # Go to download page
        ms_download_page = requests.get(
            'https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653',
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        ).content.decode('utf-8').split('\n')

        # Grab download link
        for line in ms_download_page:
            if 'click here' in line:
                link = re.search('href="(.+?)"', line.strip()).group(1)

        # Download IP list
        azure_subnets = requests.get(
            link,
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        )

        # Decode from a bytes object and split into a list of lines
        return azure_subnets.content.decode('utf-8').split('\n')


    def _process_source(self):
        try:
            # Get the source data
            azure_subnets = self._get_source()
        except:
            return self.ip_list

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
                if ip not in self.ip_list:
                    self.workingfile.write(REWRITE['COND_IP'].format(IP=ip))
                    self.ip_list.append(ip)  # Keep track of all things added
                    count += 1

        self.workingfile.write("\t# Microsoft Azure IP Count: %d\n" % count)

        # Ensure there are conditions to catch
        if count > 0:
            # Add rewrite rule... I think this should help performance
            self.workingfile.write("\n\t# Add RewriteRule for performance\n")
            self.workingfile.write(REWRITE['END_COND'])
            self.workingfile.write(REWRITE['RULE'])

        return self.ip_list



class Office365(Base):
    """
    Add Microsoft Office365 IPs: https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7
    https://rhinosecuritylabs.com/social-engineering/bypassing-email-security-url-scanning/

    :param workingfile: Open file object where rules are written
    :param headers:     HTTP headers
    :param timeout:     HTTP timeout
    :param ip_list:     List of seen IPs
    :param host_list:   List of seen Hosts
    """

    def __init__(self, workingfile, headers, timeout, ip_list, host_list):
        self.workingfile = workingfile
        self.headers     = headers
        self.timeout     = timeout
        self.ip_list     = ip_list
        self.host_list   = host_list

        self.return_data = self._process_source()


    def _get_source(self):
        # Write comments to working file
        print("[*]\tPulling Microsoft Office 365 IP/Host list...")
        self.workingfile.write("\n\n\t# Adding Microsoft Office 365 IP/Host space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

        o365_networks = requests.get(
            'https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919976789a7',
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        )

        # Return JSON object
        return o365_networks.json()


    def _process_source(self):
        try:
            # Get the source data
            o365_networks = self._get_source()
        except:
            return (self.ip_list, self.host_list)

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
                self.workingfile.write("\t# %s\n" % network['serviceAreaDisplayName'])
                # If we have URLs, lets document them
                if 'urls' in network.keys():
                    for url in network['urls']:

                        # Fix wildcard URL's to work with regex
                        if url.startswith('*'):
                            url = '.' + url

                        url = '^%s$' % url  # Add regex style to host

                        if url not in self.host_list and url != '':
                            self.workingfile.write(REWRITE['COND_HOST'].format(HOSTNAME=url))
                            self.host_list.append(url)
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
                            if ip not in self.ip_list and ip != '':
                                self.workingfile.write(REWRITE['COND_IP'].format(IP=ip))
                                self.ip_list.append(ip)  # Keep track of all things added
                                count_ip += 1

        self.workingfile.write("\t# Office 365 Host Count: %d\n" % count_host)
        self.workingfile.write("\t# Office 365 IP Count:   %d\n" % count_ip)

        # Ensure there are conditions to catch
        if count_ip > 0 or count_host > 0:
            # Add rewrite rule... I think this should help performance
            self.workingfile.write("\n\t# Add RewriteRule for performance\n")
            self.workingfile.write(REWRITE['END_COND'])
            self.workingfile.write(REWRITE['RULE'])

        return (self.ip_list, self.host_list)