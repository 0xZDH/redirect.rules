#!/usr/bin/env python3

import re
import requests
import subprocess
from datetime import datetime

# Import static data
from core.data import ips, asns, misc, agents, hostnames
from core.support import REWRITE

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


#> ----------------------------------------------------------------------------
# User-Agents Lists
def write_static_agents(workingfile, agent_list):
    # User-Agents Lists Sources
    #   -- @curi0usJack and @violentlydave
    #   -- Malware Kit
    static_agents = {
        '@curi0usJack/@violentlydave': agents.jack_agents,
        'Obtained via Malware Kit': agents.malware_kit_agents
    }

    # Add custom User-Agent list
    print("[*]\tAdding conditions for bad User-Agents...")
    workingfile.write("\n\n\t# Bad User Agents: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

    count = 0
    for source in static_agents.keys():
        workingfile.write("\n\t# Source: %s\n" % source)
        for agent in static_agents[source]:
            if agent not in agent_list:
                workingfile.write(REWRITE['COND_AGENT'].format(AGENT=agent))
                agent_list.append(agent)  # Keep track of all things added
                count += 1

    workingfile.write("\t# Bad User Agent Count: %d\n" % count)

    # Ensure there are conditions to catch
    if count > 0:
        # Add rewrite rule... I think this should help performance
        workingfile.write("\n\t# Add RewriteRule for performance\n")
        workingfile.write(REWRITE['END_COND'])
        workingfile.write(REWRITE['RULE'])

    return agent_list


#> ----------------------------------------------------------------------------
# IPs and Hostnames obtained via Malware Kit
def write_data_from_malware_kit(workingfile, ip_list, host_list):
    mk_ips = ips.malware_kit_ips
    mk_hostnames = hostnames.malware_kit_hostnames

    # Add hostnames and IPs obtained via Malware Kit
    print("[*]\tAdding Hostnames and IPs obtained via Malware Kit...")
    workingfile.write("\n\n\t# Hostnames/IPs obtained via Malware Kit: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

    workingfile.write("\n\t# Hostnames\n")
    count = 0
    for host in mk_hostnames:
        if host not in host_list:
            workingfile.write(REWRITE['COND_HOST'].format(HOSTNAME=host))
            host_list.append(host)  # Keep track of all things added
            count += 1

    workingfile.write("\t# Hostname Count: %d\n" % count)

    workingfile.write("\n\t# IPs\n")
    count = 0
    for ip in mk_ips:
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

    workingfile.write("\t# IP Count: %d\n" % count)

    # Ensure there are conditions to catch
    if count > 0:
        # Add rewrite rule... I think this should help performance
        workingfile.write("\n\t# Add RewriteRule for performance\n")
        workingfile.write(REWRITE['END_COND'])
        workingfile.write(REWRITE['RULE'])
    
    return (ip_list, host_list)


#> -----------------------------------------------------------------------------
# Add companies by ASN - via whois.radb.net
# NOTE: This is __static__ because the ASN list we are using is static
def write_asn_radb(workingfile, ip_list, args):
    # Individual Company ASNs
    #   -- @curi0usJack and @violentlydave
    #   :Format: CompanyName_AS12345
    asn_list = asns.asns
    asn_list = [x.upper() for x in asn_list]

    for asn in asn_list:
        if any(x.upper() in asn for x in args.exclude):
            continue  # Skip ASN if excluded

        asn = asn.split('_')

        print("[*]\tPulling %s -- %s via RADB..." % (asn[1], asn[0]))
        workingfile.write("\n\n\t# Live copy of %s ips based on RADB ASN %s: %s\n" % (
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
            if ip not in ip_list:
                workingfile.write(REWRITE['COND_IP'].format(IP=ip))
                ip_list.append(ip)  # Keep track of all things added
                count += 1

        workingfile.write("\t# %s - %s Count: %d\n" % (asn[0], asn[1], count))

        # Ensure there are conditions to catch
        if count > 0:
            # Add rewrite rule... I think this should help performance
            workingfile.write("\n\t# Add RewriteRule for performance\n")
            workingfile.write(REWRITE['END_COND'])
            workingfile.write(REWRITE['RULE'])

    return ip_list


#> -----------------------------------------------------------------------------
# Add companies by ASN - via BGPView
# NOTE: This is __static__ because the ASN list we are using is static
def write_asn_bgpview(headers, timeout, workingfile, ip_list, args):
    # Individual Company ASNs
    #   -- @curi0usJack and @violentlydave
    #   :Format: CompanyName_AS12345
    asn_list = asns.asns
    asn_list = [x.upper() for x in asn_list]

    for asn in asn_list:
        if any(x.upper() in asn for x in args.exclude):
            continue  # Skip ASN if excluded

        asn = asn.split('_')

        print("[*]\tPulling %s -- %s via BGPView..." % (asn[1], asn[0]))
        workingfile.write("\n\n\t# Live copy of %s ips based on BGPView ASN %s: %s\n" % (
            asn[0],
            asn[1],
            datetime.now().strftime("%Y%m%d-%H:%M:%S")
        ))

        asn_data = requests.get(
            'https://api.bgpview.io/asn/%s/prefixes' % asn[1],
            headers=headers,
            timeout=timeout,
            verify=False
        ).json()

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
                if ip not in ip_list:
                    workingfile.write(REWRITE['COND_IP'].format(IP=ip))
                    ip_list.append(ip)  # Keep track of all things added
                    count += 1

        except KeyError:
            pass

        workingfile.write("\t# %s - %s Count: %d\n" % (asn[0], asn[1], count))

        # Ensure there are conditions to catch
        if count > 0:
            # Add rewrite rule... I think this should help performance
            workingfile.write("\n\t# Add RewriteRule for performance\n")
            workingfile.write(REWRITE['END_COND'])
            workingfile.write(REWRITE['RULE'])

    return ip_list


#> -----------------------------------------------------------------------------
# Misc sources -- see data/misc.py for reasons
def write_misc(workingfile, ip_list):
    # Misc sources (seen in phishing attempts/etc.)
    #   -- @curi0usJack and @violentlydave
    #   :Format: ipORnetwork-Ownername-Reason
    misc_list = misc.misc

    print("[*]\tAdding Misc Sources")
    workingfile.write("\n\n\t# Misc Sources: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

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
        if ip not in ip_list:
            workingfile.write(REWRITE['COND_IP'].format(IP=ip))
            ip_list.append(ip)  # Keep track of all things added
            count += 1

    workingfile.write("\t# Misc IP Count: %d\n" % count)

    # Ensure there are conditions to catch
    if count > 0:
        # Add rewrite rule... I think this should help performance
        workingfile.write("\n\t# Add RewriteRule for performance\n")
        workingfile.write(REWRITE['END_COND'])
        workingfile.write(REWRITE['RULE'])

    return ip_list