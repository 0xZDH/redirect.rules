#!/usr/bin/env python3

# Based on:
#   https://github.com/0xdade/sephiroth/blob/master/providers/provider.py

# Import source modules
from core.sources.tor import Tor
from core.sources.asn import RADB, BGPView
from core.sources.misc import Misc
from core.sources.amazon import AWS
from core.sources.oracle import OracleCloud
from core.sources.google import GoogleCloud
from core.sources.htaccess import HTAccess
from core.sources.microsoft import Azure, Office365
from core.sources.useragents import UserAgents
from core.sources.malwarekit import MalwareKit


source_map = {
	'tor':         Tor,
	'aws':         AWS,
	'radb':        RADB,
	'misc':        Misc,
	'azure':       Azure,
	'bgpview':     BGPView,
	'htaccess':    HTAccess,
	'office365':   Office365,
	'malwarekit':  MalwareKit,
	'user-agents': UserAgents,
	'oraclecloud': OracleCloud,
	'googlecloud': GoogleCloud
}

class Source(object):

	def __init__(self, source, params):
		self.source = source_map[source](*params)

	def process_data(self):
		return self.source.process_data()