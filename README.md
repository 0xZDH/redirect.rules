# redirect.rules
Redirect Rules Generation Tool.

This is a Python rewrite and expansion of:
* https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
* https://github.com/violentlydave/mkhtaccess_red/blob/master/mkhtaccess_red

This tool dynamically generates a redirect.rules file that will redirect Sandbox environments away from our payload hosting/C2 servers.

### Usage
```
usage: redirect_rules.py [-h] [-d DOMAIN] [--exclude EXCLUDE [EXCLUDE ...]]
                         [--exclude-file EXCLUDE_FILE] [--exclude-list]
                         [--verbose]

Dynamically generate redirect.rules file -- v1.2

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Destination URL for redirects.
  --exclude EXCLUDE [EXCLUDE ...]
                        Pass in one or more data sources and/or specific
                        IP/Host/User-Agent's to exclude. Run the `--exclude-
                        list` command to list all data source keywords that
                        can be used. Keywords and explicit strings should be
                        space delimited. Example Usage: --exclude agents radb
                        35.0.0.0/8
  --exclude-file EXCLUDE_FILE
                        File containing items/group keywords to exclude (line
                        separated).
  --exclude-list        List all possible exclusions.
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
> python3 redirect_rules.py -d test.com --exclude tor azure 35.0.0.0/8
```

#### Exclusion List
```
[+] Exclusion List:
    --------------

        This list represents the value(s) a user can pass to the `--exclude` argument in order
        to exclude a specific data source from being added to the final redirect.rules file.
        NOTE: The `--exclude` argument accepts keywords and/or specific IP/Host/User-Agent's
        to be excluded delimited by: SPACE

        Example usage of the `--exclude` argument:
                --exclude user-agents radb 35.0.0.0/8

        Exclusion Keyword List:
        ----------------------
                dynamic         # Exclude all dynamic sources
                static          # Exclude all static sources
                htaccess        # Exclude @curi0usJack's .htaccess file
                user-agents
                malwarekit
                radb            # Exclude ASN data from RADB
                bgpview         # Exclude ASN data from BGPView
                AS#             # Exclude a specific ASN based on AS# format
                misc
                tor
                aws
                googlecloud
                microsoft
                azure
                office365
                oraclecloud
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