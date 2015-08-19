#!/usr/bin/env python


import subprocess
import json
import os
import sys
import shlex
import readline
import logging
import re
import atexit

logging.basicConfig(filename='/tmp/butcher.log', level=logging.DEBUG)

BUTCHER_DIR = os.path.join(os.environ['HOME'], '.butcher')

def load_hosts(env = None, cached=True):
    result = []
    cache_filename = os.path.join(BUTCHER_DIR, 'cache.json')
    if not cached or not os.path.isfile(cache_filename):
        if not os.path.isdir(BUTCHER_DIR):
            os.mkdir(BUTCHER_DIR)
        f = open(cache_filename, 'w')
        cmd = shlex.split("knife search node '*' -a roles -a hostname -a chef_environment -F json")
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        data = json.load(p.stdout)
        print "Loaded {} hosts".format(data['results'])
        json.dump(data['rows'], f)
        f.close()
        result = data['rows']
    else:
        f = open(cache_filename, 'r')
        result = json.load(f)

    return result

def filter_hosts(hosts, role=None, env=None):
    logging.debug('filtering role %s env %s', role, env)
    for host in (h for h in hosts if role in h['roles']):
        if env == None or env == host['chef_environment']:
            yield host

def parse_and_run(command):
    m = re.match("^\s*(?P<cmd>\w+)\s+%(?P<role>[-_A-Za-z0-9]+)(?:@(?P<env>[-_A-Za-z0-9]+))?\s*(?P<args>.+)*$", command)
    if m:
        filtered_hosts = list(filter_hosts(hosts, role=m.group('role'), env=m.group('env')))
        if m.group('cmd') == 'hostlist':
            for host in filtered_hosts:
                print host['hostname']
        elif m.group('cmd') == 'p_exec':
            cmd = shlex.split("shmux -c '{}' -".format(m.group('args')))
            logging.debug("Executing '%s' on %s", cmd, ','.join( (h['hostname'] for h in filtered_hosts) ))
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
            ret = p.communicate(input='\n'.join((h['hostname'] for h in filtered_hosts)) + '\n' )
            logging.debug("Return is %s", ret)
    else:
        print "Cannot parse command"

class CommandCompleter(object):

    def __init__(self, commands=[], roles=[], envs=[]):
        self.commands = sorted(commands)
        self.roles = sorted(roles)
        self.envs = sorted(envs)
        return

    def _purify_input(self, string):
        string = re.sub("\s+", " ", string)
        string = re.sub("^\s+", "", string)
        return string

    def complete(self, text, state):
        response = None
        cmd = self._purify_input(readline.get_line_buffer())
        tokens = cmd.split(' ')
        opts = []
        logging.debug("text '%s', state %s, buffer '%s', tokens %s", text, state, readline.get_line_buffer(), tokens)
        if len(tokens) == 1:
            opts = self.commands
        elif len(tokens) == 2:
            if tokens[1].find('@') > 0:
                role = tokens[1].split('@')[0]
                logging.debug(envs)
                opts = [role + e for e in self.envs]
            else:
                opts = self.roles

        if state == 0:
            if text:
                self.matches = [s for s in opts if s and s.startswith(text)]
            else:
                self.matches = opts[:]
            logging.debug("matches %s", self.matches)

        try:
            response = self.matches[state]
        except IndexError:
            response = None
        return response

hosts = load_hosts(cached=True)
hostnames = [x['hostname'] for x in hosts]
roles = set()
envs = set()
for host in hosts:
    roles.update(['%' + role for role in host['roles']])
    envs.add('@' + host['chef_environment'])
commands = ['exec', 'p_exec', 'hostlist']

readline.parse_and_bind('tab: complete')
readline.set_completer(CommandCompleter(commands=commands, roles=roles, envs=envs).complete)
readline.set_completer_delims(' ')
histfile=os.path.join(BUTCHER_DIR, 'history')
try:
    readline.read_history_file(histfile)
except IOError:
    pass
atexit.register(readline.write_history_file, histfile)

while True:
    command = raw_input("> ")
    parse_and_run(command)

