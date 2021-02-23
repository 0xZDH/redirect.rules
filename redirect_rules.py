#!/usr/bin/env python3

#> -----------------------------------------------------------------------------

#   Quick and dirty dynamic redirect.rules generator

#   This is a Python rewrite and expansion of:
#    - https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
#    - https://github.com/violentlydave/mkhtaccess_red/blob/master/mkhtaccess_red

#   Code architecture based on:
#    - https://github.com/0xdade/sephiroth

#> -----------------------------------------------------------------------------

import os
import re
import sys
import time
import shutil
import argparse
import subprocess
from datetime import datetime

# Import modules
try:
    from core import support
    from core.source import Source

except (ModuleNotFoundError, ImportError) as e:
    print('[!]\tMissing Python module:')
    print('\t%s' % e)
    sys.exit(1)


__version__ = '1.2.4'

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
    # Static sources
    'static',       # All static sources
    'htaccess',     # Exclude @curi0usJack's .htaccess gist
    'user-agents',
    'hostnames',
    'ips',
    'asn',          # Exclude all ASN sources
    'radb',
    'bgpview',
    'misc',
    # Dynamic sources
    'dynamic',      # All dynamic sources
    'tor',
    'amazon',       # Exclude all Amazon sources
    'aws',
    'google',       # Exclude all Google sources
    'googlecloud',
    'microsoft',    # Exclude all Microsoft sources
    'azure',
    'office365',
    'oracle',       # Exclude all Oracle sources
    'oraclecloud'
]

# URL Regex
regex = re.compile(
        r'^(?:http)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)


if __name__ == '__main__':

    # Build command line arguments
    parser = argparse.ArgumentParser(description="Dynamically generate redirect.rules file -- v{VERS}".format(VERS=__version__))
    parser.add_argument('-d', '--destination', type=str, help='Destination for redirects (with the protocol, e.g., https://redirect.here/index.php).')
    parser.add_argument(
        '--exclude',
        type=str,
        nargs='+',
        help='Pass in one or more data sources and/or explicit IP/Host/User-Agent\'s to exclude. ' +
        'Run the `--exclude-list` command to list all data source keywords that can be used. ' +
        'Keywords and explicit strings should be space delimited. ' +
        'Example Usage: `--exclude agents radb 35.0.0.0/8`'
    )
    parser.add_argument('--exclude-file',   type=str, help='File containing items/keywords to exclude (line separated).')
    parser.add_argument('--exclude-list',   action='store_true', help='List possible keyword exclusions.')
    # Support for passing in extra source files
    parser.add_argument('--ip-file',        type=str, nargs='+', help='Provide one or more external IP files to use as source data.')
    parser.add_argument('--asn-file',       type=str, nargs='+', help='Provide one or more external ASN files to use as source data.')
    parser.add_argument('--hostname-file',  type=str, nargs='+', help='Provide one or more external Hostname files to use as source data.')
    parser.add_argument('--useragent-file', type=str, nargs='+', help='Provide one or more external User-Agent files to use as source data.')
    parser.add_argument('--verbose',        action='store_true', help='Enable verbose output.')
    args = parser.parse_args()


    # Exit the script if not running on a *nix based system
    # *nix required for subprocess commands like `grep` and `sed`
    if os.name != 'posix':
        print('[!]\tPlease run this script on a *nix based system.')
        sys.exit(1)

    # Exit the script if the `whois` tool is not installed to prevent silent failures
    # during ASN collection
    # shutil.which() requires Python3.3+
    if sys.version_info >= (3, 3):
        if not shutil.which('whois'):
            print('[!]\tThe `whois` tool does not appear to be installed on your system.')
            print('\tInstall command: `sudo apt install -y whois`')
            sys.exit(1)

    # Exit the script if we are below Python3.3
    else:
        print('[!]\tPython3.3+ is required to run this script.')
        sys.exit(1)

    # Print the exclusion list and exit
    if args.exclude_list:
        support.print_exclude_list()
        sys.exit()

    # If we made it past the exclude-list, make sure
    # the user provided a destination
    if args.destination:
        # Make sure this is a full URL
        if not (re.match(regex, args.destination)):
            print('[!]\t-d/--destination must include a full URL (e.g., http://example.com/index.html)')
            sys.exit(1)
    else:
        print('[!]\tThe following arguments are required: -d/--destination')
        sys.exit(1)

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

    # Add updated/modified comments from @curi0usJack's .htaccess
    WORKINGFILE.write("\t# Note: This currently requires Apache 2.4+\n")
    WORKINGFILE.write("\t#\n")
    WORKINGFILE.write("\t# Example Usage:\n")
    WORKINGFILE.write("\t# Save file as /etc/apache2/redirect.rules\n")
    WORKINGFILE.write("\t# Within your site's Apache conf file (in /etc/apache2/sites-avaiable/),\n")
    WORKINGFILE.write("\t# put the following statement near the bottom:\n")
    WORKINGFILE.write("\t# \tInclude /etc/apache2/redirect.rules\n")
    WORKINGFILE.write("\t#\n\n")

    # Add a note to the user to keep the protocol used when setting the redirect target
    WORKINGFILE.write("\t#\n")
    WORKINGFILE.write("\t# If modifying the 'REDIR_TARGET' value, please ensure to include the protocol\n")
    WORKINGFILE.write("\t# e.g. https://google.com OR http://my.domain/test.txt\n")
    WORKINGFILE.write("\t#\n")


    #> -----------------------------------------------------------------------------
    # Write @curi0usJack's .htaccess rules: https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
    if 'htaccess' not in args.exclude:  # Exclude keyword
        source = Source(
            'htaccess',
            [  # Params object
                WORKINGFILE,
                HTTP_HEADERS,
                HTTP_TIMEOUT,
                FULL_IP_LIST,
                FULL_AGENT_LIST,
                args  # This will allow us to remove sources dynamically
            ]
        )
        (FULL_IP_LIST, FULL_AGENT_LIST) = source.process_data()

    # If we skip @curi0usJack's file, we need to add a few lines...
    else:
        WORKINGFILE.write("\tDefine REDIR_TARGET %s\n\n" % args.destination)
        WORKINGFILE.write("\tRewriteEngine On\n")
        WORKINGFILE.write("\tRewriteOptions Inherit\n\n")


    #> -----------------------------------------------------------------------------
    # Add static User-Agent list
    # __static__
    if all(x not in args.exclude for x in ['agents', 'user-agents', 'static']):  # Exclude keywords
        source = Source(
            'user-agents',
            [  # Params object
                WORKINGFILE,
                FULL_AGENT_LIST
            ]
        )
        FULL_AGENT_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # Add static ips list
    # __static__
    if all(x not in args.exclude for x in ['ip', 'ips', 'static']):  # Exclude keywords
        source = Source(
            'ips',
            [  # Params object
                WORKINGFILE,
                FULL_IP_LIST
            ]
        )
        FULL_IP_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # Add static hostnames list
    # __static__
    if all(x not in args.exclude for x in ['hosts', 'hostnames', 'static']):  # Exclude keywords
        source = Source(
            'hostnames',
            [  # Params object
                WORKINGFILE,
                FULL_HOST_LIST
            ]
        )
        FULL_HOST_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # Add Tor exit nodes: https://check.torproject.org/exit-addresses
    # __dynamic__
    if all(x not in args.exclude for x in ['tor', 'dynamic']):  # Exclude keywords
        source = Source(
            'tor',
            [  # Params object
                WORKINGFILE,
                HTTP_HEADERS,
                HTTP_TIMEOUT,
                FULL_IP_LIST
            ]
        )
        FULL_IP_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # Add AWS IPs: https://ip-ranges.amazonaws.com/ip-ranges.json
    # __dynamic__
    if all(x not in args.exclude for x in ['amazon', 'aws', 'dynamic']):  # Exclude keywords
        source = Source(
            'aws',
            [  # Params object
                WORKINGFILE,
                HTTP_HEADERS,
                HTTP_TIMEOUT,
                FULL_IP_LIST
            ]
        )
        FULL_IP_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # Add GoogleCloud IPs: dig txt _cloud-netblocks.googleusercontent.com
    # __dynamic__
    if all(x not in args.exclude for x in ['google', 'googlecloud', 'dynamic']):  # Exclude keywords
        source = Source(
            'googlecloud',
            [  # Params object
                WORKINGFILE,
                FULL_IP_LIST
            ]
        )
        FULL_IP_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # Add Microsoft Azure IPs: https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653
    # __dynamic__
    if all(x not in args.exclude for x in ['microsoft', 'azure', 'dynamic']):  # Exclude keywords
        source = Source(
            'azure',
            [  # Params object
                WORKINGFILE,
                HTTP_HEADERS,
                HTTP_TIMEOUT,
                FULL_IP_LIST
            ]
        )
        FULL_IP_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # Add Office365 IPs: https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7
    # https://rhinosecuritylabs.com/social-engineering/bypassing-email-security-url-scanning/
    # __dynamic__
    if all(x not in args.exclude for x in ['microsoft', 'office365', 'dynamic']):  # Exclude keywords
        source = Source(
            'office365',
            [  # Params object
                WORKINGFILE,
                HTTP_HEADERS,
                HTTP_TIMEOUT,
                FULL_IP_LIST,
                FULL_HOST_LIST
            ]
        )
        (FULL_IP_LIST, FULL_HOST_LIST) = source.process_data()


    #> -----------------------------------------------------------------------------
    # Add Oracle Cloud IPs: https://docs.cloud.oracle.com/en-us/iaas/tools/public_ip_ranges.json
    # __dynamic__
    if all(x not in args.exclude for x in ['orcale', 'oraclecloud', 'dynamic']):  # Exclude keywords
        source = Source(
            'oraclecloud',
            [  # Params object
                WORKINGFILE,
                HTTP_HEADERS,
                HTTP_TIMEOUT,
                FULL_IP_LIST
            ]
        )
        FULL_IP_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # Add companies by ASN - via whois.radb.net
    # __static__
    if all(x not in args.exclude for x in ['asn', 'radb', 'static']):
        source = Source(
            'radb',
            [  # Params object
                WORKINGFILE,
                FULL_IP_LIST,
                args  # This will allow us to remove sources dynamically
            ]
        )
        FULL_IP_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # Add companies by ASN - via BGPView
    # __static__
    if all(x not in args.exclude for x in ['asn', 'bgpview', 'static']):
        source = Source(
            'bgpview',
            [  # Params object
                WORKINGFILE,
                HTTP_HEADERS,
                HTTP_TIMEOUT,
                FULL_IP_LIST,
                args  # This will allow us to remove sources dynamically
            ]
        )
        FULL_IP_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # Misc sources -- see core/static/misc.txt for more information
    # __static__
    if all(x not in args.exclude for x in ['misc', 'static']):
        source = Source(
            'misc',
            [  # Params object
                WORKINGFILE,
                FULL_IP_LIST
            ]
        )
        FULL_IP_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # External sources -- IP file(s)
    if args.ip_file:
        for _file in args.ip_file:
            # Make sure the file is valid
            if os.path.isfile(_file):
                source = Source(
                    'ip-file',
                    [  # Params object
                        WORKINGFILE,
                        _file,
                        FULL_IP_LIST
                    ]
                )
                FULL_IP_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # External sources -- Hostname file(s)
    if args.hostname_file:
        for _file in args.hostname_file:
            # Make sure the file is valid
            if os.path.isfile(_file):
                source = Source(
                    'hostname-file',
                    [  # Params object
                        WORKINGFILE,
                        _file,
                        FULL_HOST_LIST
                    ]
                )
                FULL_HOST_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # External sources -- User-Agents file(s)
    if args.useragent_file:
        for _file in args.useragent_file:
            # Make sure the file is valid
            if os.path.isfile(_file):
                source = Source(
                    'useragent-file',
                    [  # Params object
                        WORKINGFILE,
                        _file,
                        FULL_AGENT_LIST
                    ]
                )
                FULL_AGENT_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # External sources -- ASN file(s)
    if args.asn_file:
        for _file in args.asn_file:
            # Make sure the file is valid
            if os.path.isfile(_file):
                source = Source(
                    'asn-file',
                    [  # Params object
                        WORKINGFILE,
                        _file,
                        FULL_IP_LIST
                    ]
                )
                FULL_IP_LIST = source.process_data()


    #> -----------------------------------------------------------------------------
    # Rule clean up and file finalization

    # Now that we have written the sink-hole rules, let's add some example rules for
    # the user to reference/use for file/path handling and a catch-all redirection

    # Handle redirection of a file/path to its final file/path destination
    WORKINGFILE.write("\n\n\t# Redirect a file/path to a target backend file/path\n")
    WORKINGFILE.write("\t# -> Example: Redirect displayed path to raw path to grab 'example.zip'\n")
    WORKINGFILE.write("\t# -> Note: This should come after all IP/Host/User-Agent blacklisting\n\n")
    WORKINGFILE.write("\t# RewriteRule\t\t\t\t^/test/files/example.zip(.*)$\t\t/example.zip\t[L,R=302]\n\n")

    # Handle redirection for a file/path to another server
    WORKINGFILE.write("\n\t# Redirect and proxy a file/path to another system's file/path\n")
    WORKINGFILE.write("\t# -> Example: Redirect and proxy displayed path to another system via the same path\n")
    WORKINGFILE.write("\t# -> Note: You can also specify the URI explicitly as needed\n")
    WORKINGFILE.write("\t# -> Note: This should come after all IP/Host/User-Agent blacklisting\n\n")
    WORKINGFILE.write("\t# RewriteRule\t\t\t\t^/test/files/example.zip(.*)$\t\thttps://192.168.10.10%{REQUEST_URI}\t[P]\n\n")

    # Create a final, catch-all redirection
    WORKINGFILE.write("\n\t# Catch-all redirect\n")
    WORKINGFILE.write("\t# -> Example: Catch anything other than '/example.zip' and redirect\n")
    WORKINGFILE.write("\t# -> Note: This should be the last item in the redirect.rules file as a final catch-all\n\n")
    WORKINGFILE.write("\t# RewriteRule\t\t\t\t^((?!\\/example\\.zip).)*$\t\t${REDIR_TARGET}\t[L,R=302]\n")

    print("\n[+]\tFile/Path redirection and catch-all examples commented at bottom of file.\n")

    # Add a note at the end of the rules file of what was excluded...
    if len(args.exclude) > 0:
        WORKINGFILE.write("\n\n\t#\n")
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

    print("\n[*]\tPerforming rule de-duplication clean up...")

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
