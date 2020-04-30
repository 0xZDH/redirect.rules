#!/usr/bin/env python3

import os
import re
from datetime import datetime

# Import static data
from core.support import REWRITE

# Import parent class
from core.base import Base


class Misc(Base):
    """
    Misc sources -- see static/misc.txt for reasons

    :param workingfile: Open file object where rules are written
    :param ip_list:     List of seen IPs
    """

    def __init__(self, workingfile, ip_list):
        self.workingfile = workingfile
        self.ip_list     = ip_list

        self.return_data = self._process_source()


    def _get_source(self):
        # Read in static source file from static/ dir
        misc_list = []
        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/misc.txt', 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    misc_list.append(line)

        return misc_list


    def _process_source(self):
        try:
            # Get the source data
            misc_list = self._get_source()
        except:
            return self.ip_list

        print("[*]\tAdding Miscellaneous Sources...")
        self.workingfile.write("\n\n\t# Misc Sources: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

        count = 0
        for obj in misc_list:
            obj = obj.split('-')
            ip  = obj[0]
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

        self.workingfile.write("\t# Misc IP Count: %d\n" % count)

        # Ensure there are conditions to catch
        if count > 0:
            # Add rewrite rule... I think this should help performance
            self.workingfile.write("\n\t# Add RewriteRule for performance\n")
            self.workingfile.write(REWRITE['END_COND'])
            self.workingfile.write(REWRITE['RULE'])

        return self.ip_list