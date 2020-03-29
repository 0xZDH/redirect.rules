#!/usr/bin/env python3

import re
import requests
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


#> ----------------------------------------------------------------------------
# @curi0usJack's .htaccess rules: https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
# Current raw gist link as of: March 27, 2020
def write_jack_htaccess(headers, timeout, workingfile, ip_list, agent_list, args):
    print("[*]\tPulling @curi0usJack's redirect rules...")
    workingfile.write("\n\n\t# @curi0usJack .htaccess: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

    # Split the lines via new-line since its a raw txt file being processed
    htaccess_file = requests.get(
        'https://gist.githubusercontent.com/curi0usJack/971385e8334e189d93a6cb4671238b10/raw/13b11edf67f746bdd940ff3f2e9b8dc18f8ad7d4/.htaccess',
        headers=headers,
        timeout=timeout,
        verify=False
    ).content.decode('utf-8').split('\n')

    # Write the file contents to our local redirect.rules, but remove
    # commenting at top of file - replaced by our own modified commenting
    print("[*]\tWriting @curi0usJack's redirect rules...")

    # Keep count of the IP/User-Agents documented
    count_ip = 0
    count_ua = 0

    # Skip the header comments since we write our own version
    # This means that the line offset is: 12
    htaccess_file = htaccess_file[11:]

    # Line offsets based on comments removed from the start of file
    START = 12
    STOP  = 11  # Take away 1 for end of slice

    file_headers = htaccess_file[(11-START):(21-STOP)]

    # Data Groups
    # Use comma delimited strings as the key since there are a few groups that
    # can be excluded with multiple keywords
    file_groups = {
        'aws,azure':       htaccess_file[(22-START):(31-STOP)],
        'aws':             htaccess_file[(32-START):(114-STOP)],
        'forcepoint':      htaccess_file[(115-START):(119-STOP)],
        'domaintools':     htaccess_file[(120-START):(122-STOP)],
        'zscaler':         htaccess_file[(123-START):(126-STOP)],
        'misc':            htaccess_file[(127-START):(137-STOP)],
        'virustotal':      htaccess_file[(138-START):(151-STOP)],
        'trendmicro':      htaccess_file[(152-START):(172-STOP)],
        'bluecoat':        htaccess_file[(173-START):(177-STOP)],
        'urlquery':        htaccess_file[(178-START):(189-STOP)],
        'paloalto':        htaccess_file[(190-START):(207-STOP)],
        'proofpoint':      htaccess_file[(208-START):(224-STOP)],
        'messagelabs':     htaccess_file[(225-START):(249-STOP)],
        'fortigate':       htaccess_file[(250-START):(267-STOP)],
        'symantec':        htaccess_file[(268-START):(306-STOP)],
        'microsoft':       htaccess_file[(307-START):(310-STOP)],
        'microsoft,azure': htaccess_file[(311-START):(435-STOP)],
        'user-agents':     htaccess_file[(437-START):(443-STOP)],
        'barracuda':       htaccess_file[(444-START):(447-STOP)],
        'slackbot':        htaccess_file[(448-START):(451-STOP)],
        'tor':             htaccess_file[(452-START):-1]  # Go until EOF
    }


    # Let's start by writing the file headers
    for line in file_headers:
        # Add user-supplied redirect destination
        if 'DESTINATIONURL' in line:
            line = re.sub('\|DESTINATIONURL\|', args.domain, line)

        workingfile.write(line + '\n')  # New-line was removed on split earlier


    # Now let's write each group, but only those the user has not
    # excluded
    for group in file_groups.keys():
        # Now we need cross reference our exclude list and the keys...
        if all(x not in args.exclude for x in group.split(',')):
            for line in file_groups[group]:
                workingfile.write(line + '\n')  # New-line was removed on split earlier

                # Check for IPs to keep a list for de-duping
                if all(x in line for x in ['RewriteCond', 'expr']):
                    ip_list.append(line.split("'")[1])
                    count_ip += 1

                # Check for User-Agents to keep a list for de-duping
                if all(x in line for x in ['RewriteCond', 'HTTP_USER_AGENT']):
                    if '"' in line:  # This is specific to one of the user-agents
                        agent_list.append(re.search('"(.+)"', line).group(1))
                    else:
                        agent_list.append(re.search('(\^.+\$)', line).group(1))

                    count_ua += 1

    workingfile.write("\t# @curi0usJack IP Count:         %d\n" % count_ip)
    workingfile.write("\t# @curi0usJack User Agent Count: %d\n" % count_ua)

    return (ip_list, agent_list)