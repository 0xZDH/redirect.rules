# redirect.rules
Redirect Rules Generation Tool.

This is a Python rewrite and expansion of:
* https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
* https://github.com/violentlydave/mkhtaccess_red/blob/master/mkhtaccess_red

This tool dynamically generates a redirect.rules file that will redirect Sandbox environments away from our payload hosting/C2 servers.

### Usage
```
usage: redirect_rules.py [-h] (-d DOMAIN | --exclude-list)
                         [--exclude EXCLUDE [EXCLUDE ...]] [--verbose]

Dynamically generate redirect.rules file -- v1.2

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Destination URL for redirects.
  --exclude-list        List all possible exclusions.
  --exclude EXCLUDE [EXCLUDE ...]
                        Pass in one or more IP/Host/User-Agent groups to
                        exclude.
  --verbose             Enable verbose output.
```

#### Example Run
```
> python3 redirect_rules.py -d test.com

    ----------------------------------
    Redirect Rules Generation Tool
                v1.2
    ----------------------------------

[*]     Pulling @curi0usJack's redirect rules...
[*]     Writing @curi0usJack's redirect rules...
[*]     Adding conditions for bad User-Agents...
[*]     Adding Hostnames and IPs obtained via Malware Kit...
[*]     Pulling TOR exit node list...
[*]     Pulling AWS IP/Network list...
[*]     Pulling Google Cloud IP/network list...
[*]     Pulling Microsoft Azure IP/network list...
[*]     Pulling Office 365 IP list...
[*]     Pulling Oracle Cloud IP list...
[*]     Pulling AS46484 -- McAfee via RADB...
...
[*]     Pulling AS13448 -- ForcePoint via BGPView...
[*]     Adding Misc Sources

[*]     Performing rule de-duplication clean up...
[*]     Removing 408 duplicate IPs/Networks...

[+]     Total IPs, Networks or User-Agents blocked: 9164
[+]     Redirect rules file: /tmp/redirect.rules

redirect_rules.py executed in 59.55 seconds.
```

Example exclusion usage - Exclude Google Cloud and Microsoft Azure:
```
> python3 redirect_rules.py -d test.com --exclude google azure
```

#### Exclusion List
```
[+] Exclusion List:
    --------------

        Exclude all dynamic sources:
                `dynamic`
        Exclude all static sources:
                `static`

        Static Sources:
        --------------
        Exclude User-Agents:
                `agents`, `user-agents`
        Exclude data via Malware Kit:
                `mk`, `malware`, `malwarekit`
        Exclude ASN via RADB:
                `radb`, `asnradb`
        Exclude ASN via BGPView:
                `bgpview`, `asnbgpview`
        Exclude Miscelenaeous:
                `misc`

        Dynamic Sources:
        ---------------
        Exclude curi0usJack .htaccess:
                `jack`, `htaccess`, `curiousjack`
        Exclude Tor Exit Nodes:
                `tor`
        Exclude AWS:
                `aws`
        Exclude Google Cloud:
                `google`, `googlecloud`
        Exclude Microsoft Azure:
                `azure`
        Exclude Office 365:
                `o365`, `office`, `office365`
        Exclude Oracle Cloud:
                `oracle`, `oraclecloud`
```

> All static data is stored within the core/data/ directory in .py files as Python objects. If you need to remove an ASN/User-Agent/IP/etc. from a static list, open the corresponding Python file and comment out what you no longer require. If you need to add anything, follow the :format: at the top of the Python data file (if present).

### Requirements
```
pip3 install -r requirements.txt
```

### Acknowledgements
**@curi0usJack** - https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10<br>
**@violentlydave** - [mkhtaccess_red](https://github.com/violentlydave/mkhtaccess_red/)

### TODO
* Reorder groups by most likely to be seen
* Sort IPs/Hosts/Agents in each grouping
* Build an index at the top of redirect.rules based on starting line number of each grouping
* Custmoize rewrite rule(s) to redirect differently based on user-agent