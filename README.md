# redirect_rules
Redirect Rules Generation Tool.

This is a Python rewrite and expansion of:
* https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
* https://github.com/violentlydave/mkhtaccess_red/blob/master/mkhtaccess_red

This tool dynamically generates a redirect.rules file that will redirect Sandbox environments away from our payload hosting/C2 servers.

#### Usage
```
usage: redirect_rules.py [REDIRECT_DOMAIN]
```

```
$ python3 redirect_rules.py examplee.com                     

----------------------------------
  Redirect Rules Generation Tool
               v1.0
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
[*]     Removing 409 duplicate IPs/Networks...

[*]     Total IPs, Networks or User-Agents blocked: 9353
[*]     Redirect rules file: /tmp/redirect.rules

redirect_rules.py executed in 92.93 seconds.
```

> All static data is stored within the data/ directory in .py files as Python objects. If you need to remove an ASN/User-Agent/IP/etc. from a static list, open the corresponding Python file and comment out what you no longer require. If you need to add anything, follow the :format: at the top of the Python data file (if present).

#### Requirements
```
pip3 install -r requirements.txt
```

#### Acknowledgements
**curi0usJack** - https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10<br>
**violentlydave** - [mkhtaccess_red](https://github.com/violentlydave/mkhtaccess_red/)

#### TODO
* Sort IPs/Hosts/Agents in each grouping
* Build an index at top of redirect.rules based on starting line number of each grouping
* Custmoize rewrite rule(s) to redirect differently based on user-agent