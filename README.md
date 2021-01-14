# redirect.rules

Redirect Rules Generation Tool.

This is a Python rewrite and expansion of:
* https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
* https://github.com/violentlydave/mkhtaccess_red/blob/master/mkhtaccess_red

Code architecture based on:
* https://github.com/0xdade/sephiroth

This tool dynamically generates a redirect.rules file that will redirect Sandbox environments away from our payload hosting/C2 servers.

## Requirements

```bash
# Install the required Python dependencies
  pip3 install -r requirements.txt

# Install the 'whois' tool
  sudo apt install -y whois

# Enable 'mod_rewrite' for Apache
  sudo a2enmod rewrite
```

Included is a setup.sh script that will automate the installation of all required dependencies:
```
sudo ./setup.sh
```

## Usage

```
usage: redirect_rules.py [-h] [-d DESTINATION]
                         [--exclude EXCLUDE [EXCLUDE ...]]
                         [--exclude-file EXCLUDE_FILE] [--exclude-list]
                         [--ip-file IP_FILE [IP_FILE ...]]
                         [--asn-file ASN_FILE [ASN_FILE ...]]
                         [--hostname-file HOSTNAME_FILE [HOSTNAME_FILE ...]]
                         [--useragent-file USERAGENT_FILE [USERAGENT_FILE ...]]
                         [--verbose]

Dynamically generate redirect.rules file -- v1.2.2

optional arguments:
  -h, --help            show this help message and exit
  -d DESTINATION, --destination DESTINATION
                        Destination for redirects (with the protocol, e.g., https://redirect.here/index.php).
  --exclude EXCLUDE [EXCLUDE ...]
                        Pass in one or more data sources and/or explicit
                        IP/Host/User-Agent's to exclude. Run the `--exclude-
                        list` command to list all data source keywords that
                        can be used. Keywords and explicit strings should be
                        space delimited. Example Usage: `--exclude agents radb
                        35.0.0.0/8`
  --exclude-file EXCLUDE_FILE
                        File containing items/group keywords to exclude (line
                        separated).
  --exclude-list        List all possible exclusions.
  --ip-file IP_FILE [IP_FILE ...]
                        Provide one or more IP files to use as source data.
  --asn-file ASN_FILE [ASN_FILE ...]
                        Provide one or more ASN files to use as source data.
  --hostname-file HOSTNAME_FILE [HOSTNAME_FILE ...]
                        Provide one or more Hostname files to use as source
                        data.
  --useragent-file USERAGENT_FILE [USERAGENT_FILE ...]
                        Provide one or more User-Agent files to use as source
                        data.
  --verbose             Enable verbose output.
```

#### Example Run
```
> python3 redirect_rules.py -d https://test.com

    ----------------------------------
      Redirect Rules Generation Tool
                  v1.2.2
    ----------------------------------

[*]     Pulling @curi0usJack's redirect rules...
[*]     Writing @curi0usJack's redirect rules...
[*]     Adding conditions for bad User-Agents...
[*]     Adding static IPs obtained via Malware Kit's and other sources...
[*]     Adding static Hostnames obtained via Malware Kit's and other sources...
[*]     Pulling TOR exit node list...
[*]     Pulling AWS IP/Network list...
[*]     Pulling Google Cloud IP/network list...
[*]     Pulling Microsoft Azure IP/network list...
[*]     Pulling Office 365 IP list...
[*]     Pulling Oracle Cloud IP list...
[*]     Pulling AS46484 -- McAfee via RADB...
...
[*]     Pulling AS13448 -- ForcePoint via BGPView...
[*]     Adding Miscellaneous Sources...

[*]     Performing rule de-duplication clean up...
[*]     Removing 408 duplicate IPs/Networks...

[+]     Total IPs, Networks or User-Agents blocked: 9164
[+]     Redirect rules file: /tmp/redirect.rules

redirect_rules.py executed in 59.55 seconds.
```

#### Example Usage

```bash
# Example exclusion usage - Exclude Tor, Microsoft Azure, and an explicit CIDR:
  python3 redirect_rules.py -d https://test.com --exclude tor azure 35.0.0.0/8

# Example external source file usage - Include external IP list for redirection:
  python3 redirect_rules.py -d https://test.com --ip-file new_ip_list.txt

# Example usage to generate rules for a single external source
# This excludes all sources provided by redirect_rules and only uses the external source:
  python3 redirect_rules.py -d https://test.com --exclude htaccess dynamic static --ip-file new_ip_list.txt
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
                user-agents     # Exclude User-Agents file
                ips             # Exclude IPs obtained via Malware Kit's and other sources
                hostnames       # Exclude Hostnames obtained via Malware Kit's and other sources
                asn             # Exclude all ASN data
                radb            # Exclude ASN data from RADB
                bgpview         # Exclude ASN data from BGPView
                AS#             # Exclude a specific ASN based on AS# format
                misc            # Exclude Misc data sources
                tor             # Exclude TOR Exit Node data
                amazon          # Exclude all Amazon data
                aws             # Exclude AWS data
                google          # Exclude all Google data
                googlecloud     # Exclude Google Cloud data
                microsoft       # Exclude all Microsoft data
                azure           # Exclude MS Azure data
                office365       # Exclude Office365 data
                oracle          # Exclude all Oracle data
                oraclecloud     # Exclude Oracle Cloud data

        NOTE: Company names/identifiers used within the core/data/asns.py
        file can also be used.
        Exclude All ZScaler ASN's: `--exclude ZSCALER`
        Exclude ZScaler's ATL ASN: `--exclude ZSCALER-ATLANTA`
```

> All static data is stored within the core/data/ directory in .py files as Python objects. If you need to remove an ASN/User-Agent/IP/etc. from a static list, open the corresponding Python file and comment out what you no longer require. If you need to add anything, follow the :format: at the top of the Python data file (if present).

### Docker
```bash
# Build docker
  docker build --tag=redirect_rules .

# Run docker attaching /tmp
  docker run --rm -v /tmp:/tmp redirect_rules -d https://test.com

# Run docker attaching current directory
  docker run --rm -v $(pwd):/tmp redirect_rules -d https://test.com

# Once the run completes, the `redirect.rules` file will be located
# in the directory attached to the docker run.
```

#### Run With Exclusions
```bash
# Run with exclude list:
  docker run --rm -v /tmp:/tmp redirect_rules -d https://test.com --exclude aws azure 35.0.0.0/8

# Run with an exclude file:
  docker cp exclude.txt <CONTAINER>:/app/exclude.txt
  docker run --rm -v /tmp:/tmp redirect_rules -d https://test.com --exclude-file exclude.txt
```

### Acknowledgements

**@curi0usJack** - https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10<br>
**@violentlydave** - [mkhtaccess_red](https://github.com/violentlydave/mkhtaccess_red/)<br>
**@0xdade** - [sephiroth](https://github.com/0xdade/sephiroth)

### TODO

* Add better exception handling
* Reorder groups by most likely to be seen
* Sort IPs/Hosts/Agents in each grouping
* Build an index at the top of redirect.rules based on starting line number of each grouping
* Custmoize rewrite rule(s) to redirect differently based on user-agent