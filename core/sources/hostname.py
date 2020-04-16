#!/usr/bin/env python3

import os
import re
from datetime import datetime

# Import static data
from core.support import REWRITE

# Import parent class
from core.base import Base


class Hostname(Base):
    """
    Class to write static list of Hostnames that were obtained
    via Malware Kits and other sources located in core/static/hostnames.txt

    :param workingfile: Open file object where rules are written
    :param host_list:   List of seen Hosts
    """

    def __init__(self, workingfile, host_list):
        self.workingfile = workingfile
        self.host_list   = host_list

        self.return_data = self._process_source()


    def _get_source(self):
        # Read in static source file from static/ dir
        hostnames = []
        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/hostnames.txt', 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    hostnames.append(line)

        return hostnames


    def _process_source(self):
        try:
            # Get the source data
            hostnames = self._get_source()
        except:
            return self.host_list

        # Add IPs obtained via Malware Kit's and other sources
        print("[*]\tAdding static Hostnames obtained via Malware Kit's and other sources...")
        self.workingfile.write("\n\n\t# Hostnames obtained via Malware Kit's and other sources: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

        count = 0
        for host in hostnames:
            if host not in self.host_list and host != '':
                self.workingfile.write(REWRITE['COND_HOST'].format(HOSTNAME=host))
                self.host_list.append(host)  # Keep track of all things added
                count += 1

        self.workingfile.write("\t# Hostname Count: %d\n" % count)

        # Ensure there are conditions to catch
        if count > 0:
            # Add rewrite rule... I think this should help performance
            self.workingfile.write("\n\t# Add RewriteRule for performance\n")
            self.workingfile.write(REWRITE['END_COND'])
            self.workingfile.write(REWRITE['RULE'])

        return self.host_list