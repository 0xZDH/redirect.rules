#!/usr/bin/env python3

# Based on:
#   https://github.com/0xdade/sephiroth/blob/master/providers/base_provider.py

class Base(object):

    def _get_source(self):
        raise NotImplementedError

    def _process_source(self):
        raise NotImplementedError

    def process_data(self):
    	return self.return_data