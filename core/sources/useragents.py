#!/usr/bin/env python3

from datetime import datetime

# Import static data
from core.static import agents
from core.support import REWRITE

# Import parent class
from core.base import Base


class UserAgents(Base):
    """
    User-Agents class to write static list of User-Agents from
    core/static/agents.py

    :param workingfile: Open file object where rules are written
    :param agent_list:  List of seen User-Agents
    """

    def __init__(self, workingfile, agent_list):
        self.workingfile = workingfile
        self.agent_list  = agent_list

        self.return_data = self._process_source()


    def _process_source(self):
        # User-Agents Sources
        #   -- @curi0usJack and @violentlydave
        #   -- Malware Kit
        static_agents = {
            '@curi0usJack/@violentlydave': agents.jack_agents,
            'Obtained via Malware Kit': agents.malware_kit_agents
        }

        # Add custom User-Agent list
        print("[*]\tAdding conditions for bad User-Agents...")
        self.workingfile.write("\n\n\t# Bad User Agents: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

        count = 0
        for source in static_agents.keys():
            self.workingfile.write("\n\t# Source: %s\n" % source)
            for agent in static_agents[source]:
                if agent not in self.agent_list and agent != '':
                    self.workingfile.write(REWRITE['COND_AGENT'].format(AGENT=agent))
                    self.agent_list.append(agent)  # Keep track of all things added
                    count += 1

        self.workingfile.write("\t# Bad User Agent Count: %d\n" % count)

        # Ensure there are conditions to catch
        if count > 0:
            # Add rewrite rule... I think this should help performance
            self.workingfile.write("\n\t# Add RewriteRule for performance\n")
            self.workingfile.write(REWRITE['END_COND'])
            self.workingfile.write(REWRITE['RULE'])

        return self.agent_list