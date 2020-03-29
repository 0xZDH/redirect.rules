#!/usr/bin/env python3

#> -----------------------------------------------------------------------------

#   Quick and dirty dynamic redirect.rules generator

#   This is a Python rewrite and expansion of:
#    - https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
#    - https://github.com/violentlydave/mkhtaccess_red/blob/master/mkhtaccess_red

#> -----------------------------------------------------------------------------

import os
import re
import sys
import time
import argparse
import subprocess
from datetime import datetime

# Import core modules
from core import dynamic, static, htaccess, support


__version__ = '1.2'

## Global files
LOGFILE_NAME     = '/tmp/redirect_logfile'
WORKINGFILE_NAME = '/tmp/redirect.rules'
LOGFILE     = open(LOGFILE_NAME, 'w')
WORKINGFILE = open(WORKINGFILE_NAME, 'w')

## HTTP requests config
HTTP_TIMEOUT = 10
HTTP_HEADERS = {
    'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:74.0) Gecko/20100101 Firefox/74.0"
}

## De-dupe data storage
FULL_IP_LIST    = []  # De-dupe ips
FULL_HOST_LIST  = []  # De-dupe hosts
FULL_AGENT_LIST = []  # De-dupe agents

## Exclusion Keywords
# This will allow us to identify explicit exclusions
KEYWORDS = [
    'dynamic',
    'static',
    'htaccess',
    'user-agents',
    'malwarekit',
    'radb',
    'bgpview',
    'misc',
    'tor',
    'aws',
    'googlecloud',
    'microsoft',
    'azure',
    'office365',
    'oraclecloud'
]


if __name__ == '__main__':

    # Build command line arguments
    parser = argparse.ArgumentParser(description="Dynamically generate redirect.rules file -- v{VERS}".format(VERS=__version__))
    parser.add_argument('-d', '--domain', type=str, help='Destination URL for redirects.')
    parser.add_argument(
        '--exclude',
        type=str,
        nargs='+',
        help='Pass in one or more data sources and/or explicit IP/Host/User-Agent\'s to exclude. ' +
        'Run the `--exclude-list` command to list all data source keywords that can be used. ' +
        'Keywords and explicit strings should be space delimited. ' +
        'Example Usage: `--exclude agents radb 35.0.0.0/8`'
    )
    parser.add_argument('--exclude-file', type=str, help='File containing items/group keywords to exclude (line separated).')
    parser.add_argument('--exclude-list', action='store_true', help='List all possible exclusions.')
    parser.add_argument('--verbose',      action='store_true', help='Enable verbose output.')
    args = parser.parse_args()


    # Exit the script if not running on a *nix based system
    # *nix required for subprocess commands like `grep` and `sed`
    if os.name != 'posix':
        print('[!]\tPlease run this script on a *nix based system.')
        sys.exit()

    # Print the exclusion list and exit
    if args.exclude_list:
        support.print_exclude_list()
        sys.exit()

    # If we made it past the exclude-list, make sure
    # the user provided a domain
    if not args.domain:
        print('[!]\tThe following arguments are required: -d/--domain')
        sys.exit()


    print('''
    ----------------------------------
      Redirect Rules Generation Tool
                   v{VERS}
    ----------------------------------
    '''.format(VERS=__version__))

    # Start timer
    start = time.perf_counter()

    # If no exclusions, make the variable usable
    # Not a great work around, but works for now...
    if not args.exclude:
        args.exclude = []

    # Parse exclusion file and add to exclude list
    if args.exclude_file and os.path.exists(args.exclude_file):
        with open(args.exclude_file, 'r') as file_:
            args.exclude += file_.readlines()
            args.exclude = [x.strip() for x in args.exclude if x.strip() != '']

    # Print exclusion count
    # Only show count in case a large list was passed in
    if len(args.exclude) > 0:
        print('[+]\tExclusion List: %d' % len(args.exclude))
        print('[*]\tFull exclusion list can be found at the end of the')
        print('   \tredirect.rules file.\n')

    #> ----------------------------------------------------------------------------
    # Initialize redirect.rules file
    # Add header comments to the redirect.rules file headers
    WORKINGFILE.write("\t#\n")
    WORKINGFILE.write("\t# %s v%s to block AV Sandboxes - built: %s\n" % (__file__, __version__, datetime.now().strftime("%Y%m%d-%H:%M:%S")))
    WORKINGFILE.write("\t#\n\n")

    # Add updated comments from @curi0usJack's .htaccess
    WORKINGFILE.write("\t# Note: This currently requires Apache 2.4+\n")
    WORKINGFILE.write("\t#\n")
    WORKINGFILE.write("\t# Example Usage:\n")
    WORKINGFILE.write("\t# Save file as /etc/apache2/redirect.rules\n")
    WORKINGFILE.write("\t# Within your site's Apache conf file (in /etc/apache2/sites-avaiable/),\n")
    WORKINGFILE.write("\t# put the following statement near the bottom:\n")
    WORKINGFILE.write("\t# \tInclude /etc/apache2/redirect.rules\n")
    WORKINGFILE.write("\t#\n\n")


    #> -----------------------------------------------------------------------------
    # Write @curi0usJack's .htaccess rules: https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
    # This is our starting point when included
    if all(x not in args.exclude for x in ['htaccess']):
        (FULL_IP_LIST, FULL_AGENT_LIST) = htaccess.write_jack_htaccess(
            HTTP_HEADERS,
            HTTP_TIMEOUT,
            WORKINGFILE,
            FULL_IP_LIST,
            FULL_AGENT_LIST,
            args  # This will allow us to remove sources dynamically
        )

    # If we skip @curi0usJack's file, we need to add a few lines...
    else:
        WORKINGFILE.write("\tDefine REDIR_TARGET %s\n\n" % args.domain)
        WORKINGFILE.write("\tRewriteEngine On\n")
        WORKINGFILE.write("\tRewriteOptions Inherit\n\n")


    #> -----------------------------------------------------------------------------
    # Add __static__ User-Agent list
    if all(x not in args.exclude for x in ['user-agents', 'static']):
        FULL_AGENT_LIST = static.write_static_agents(
            WORKINGFILE,
            FULL_AGENT_LIST
        )


    #> -----------------------------------------------------------------------------
    # Add __static__ hostnames and IPs obtained via Malware Kit
    if all(x not in args.exclude for x in ['malwarekit', 'static']):
        (FULL_IP_LIST, FULL_HOST_LIST) = static.write_data_from_malware_kit(
            WORKINGFILE,
            FULL_IP_LIST,
            FULL_HOST_LIST
        )


    #> -----------------------------------------------------------------------------
    # Add Tor exit nodes: https://check.torproject.org/exit-addresses
    if all(x not in args.exclude for x in ['tor', 'dynamic']):
        FULL_IP_LIST = dynamic.write_tor_nodes(
            HTTP_HEADERS,
            HTTP_TIMEOUT,
            WORKINGFILE,
            FULL_IP_LIST
        )


    #> -----------------------------------------------------------------------------
    # Add AWS IPs: https://ip-ranges.amazonaws.com/ip-ranges.json
    if all(x not in args.exclude for x in ['aws', 'dynamic']):
        FULL_IP_LIST = dynamic.write_aws(
            HTTP_HEADERS,
            HTTP_TIMEOUT,
            WORKINGFILE,
            FULL_IP_LIST
        )


    #> -----------------------------------------------------------------------------
    # Add GoogleCloud IPs: dig txt _cloud-netblocks.googleusercontent.com
    if all(x not in args.exclude for x in ['googlecloud', 'dynamic']):
        FULL_IP_LIST = dynamic.write_google_cloud(
            WORKINGFILE,
            FULL_IP_LIST
        )


    #> -----------------------------------------------------------------------------
    # Add Microsoft Azure IPs: https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653
    if all(x not in args.exclude for x in ['azure', 'dynamic']):
        FULL_IP_LIST = dynamic.write_azure(
            HTTP_HEADERS,
            HTTP_TIMEOUT,
            WORKINGFILE,
            FULL_IP_LIST
        )


    #> -----------------------------------------------------------------------------
    # Add Office365 IPs: https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7
    # https://rhinosecuritylabs.com/social-engineering/bypassing-email-security-url-scanning/
    if all(x not in args.exclude for x in ['office365', 'dynamic']):
        (FULL_IP_LIST, FULL_HOST_LIST) = dynamic.write_office_365(
            HTTP_HEADERS,
            HTTP_TIMEOUT,
            WORKINGFILE,
            FULL_IP_LIST,
            FULL_HOST_LIST
        )


    #> -----------------------------------------------------------------------------
    # Add Oracle Cloud IPs: https://docs.cloud.oracle.com/en-us/iaas/tools/public_ip_ranges.json
    if all(x not in args.exclude for x in ['oraclecloud', 'dynamic']):
        FULL_IP_LIST = dynamic.write_oracle_cloud(
            HTTP_HEADERS,
            HTTP_TIMEOUT,
            WORKINGFILE,
            FULL_IP_LIST
        )


    #> -----------------------------------------------------------------------------
    # Add companies by ASN - via whois.radb.net
    if all(x not in args.exclude for x in ['radb', 'static']):
        FULL_IP_LIST = static.write_asn_radb(
            WORKINGFILE,
            FULL_IP_LIST,
            args  # This will allow us to remove sources dynamically
        )


    #> -----------------------------------------------------------------------------
    # Add companies by ASN - via BGPView
    if all(x not in args.exclude for x in ['bgpview', 'static']):
        FULL_IP_LIST = static.write_asn_bgpview(
            HTTP_HEADERS,
            HTTP_TIMEOUT,
            WORKINGFILE,
            FULL_IP_LIST,
            args  # This will allow us to remove sources dynamically
        )


    #> -----------------------------------------------------------------------------
    # Misc sources -- see data/misc.py for reasons
    if all(x not in args.exclude for x in ['misc', 'static']):
        FULL_IP_LIST = static.write_misc(
            WORKINGFILE,
            FULL_IP_LIST
        )


    #> -----------------------------------------------------------------------------
    # Rule clean up
    # Keep in main file since we will run every time
    print("\n[*]\tPerforming rule de-duplication clean up...")

    # Add a note at the end of the rules file of what was excluded...
    if len(args.exclude) > 0:
        WORKINGFILE.write("\n\t#\n")
        if any(x in KEYWORDS or re.search('^AS',x) for x in args.exclude):
            WORKINGFILE.write("\t# The following data groups were excluded:\n")
            for item in args.exclude:
                if item in KEYWORDS:
                    WORKINGFILE.write("\t#\t%s\n" % item)

        if any(x not in KEYWORDS for x in args.exclude):
            WORKINGFILE.write("\n\t# The following explicit values were commented out:\n")
            for item in args.exclude:
                if item not in KEYWORDS:
                    WORKINGFILE.write("\t#\t%s\n" % item)

    WORKINGFILE.close()  # Close out working file before modding it via bash

    # Let's build our CIDR map to identify redundant CIDRs
    tmp_ip_list   = []
    tmp_cidr_list = {}
    for ip in FULL_IP_LIST:
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
        if ip_cidr in FULL_IP_LIST:
            ip = re.sub('\.', '\\.', ip)
            remove_list.append(ip)

    # Add user defined exclusions
    for item in args.exclude:
        # Make sure this isn't a keyword or known value
        if item not in KEYWORDS and not re.search('^AS', item):
            # Instead of trying to identify what type of data
            # the user passed... let's just escape any
            # characters needed for sed
            # Escape `.`
            item = re.sub('\.', '\\.', item)
            # Escape `/`
            item = re.sub('/', '\\/', item)
            # Escape `$`
            item = re.sub('\$', '\\$', item)
            # Escape `^`
            item = re.sub('\^', '\\^', item)
            # Escape `*`
            item = re.sub('\*', '\\*', item)
            if item not in remove_list:
                remove_list.append(item)

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
    print("\n[+]\tTotal IPs, Networks or User-Agents blocked: %d" % result)
    print("[+]\tRedirect rules file: %s" % WORKINGFILE_NAME)


    elapsed = time.perf_counter() - start
    print(f"\n{__file__} executed in {elapsed:0.2f} seconds.")