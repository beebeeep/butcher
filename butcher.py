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
import signal

logging.basicConfig(filename='/tmp/butcher.log', level=logging.DEBUG)
BUTCHER_DIR = os.path.join(os.environ['HOME'], '.butcher')

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

class Butcher(object):

    def __init__(self):
        self.commands = ['exec', 'p_exec', 'hostlist', 'reload', 'threads', 'user']
        self._shmux_running = False
        self._load_hosts()
        readline.parse_and_bind('tab: complete')
        readline.set_completer(CommandCompleter(commands=self.commands, roles=self.roles, envs=self.envs).complete)
        readline.set_completer_delims(' ')
        histfile=os.path.join(BUTCHER_DIR, 'history')
        try:
            readline.read_history_file(histfile)
        except IOError:
            pass
        atexit.register(readline.write_history_file, histfile)
        signal.signal(signal.SIGINT, self._sigint())


    def _sigint(self):
        def __handler(signal, frame):
            if self._shmux_running:
                pass
            else:
                raise KeyboardInterrupt
        return __handler

    def _load_hosts(self, env = None, cached=True):
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
            self.hosts = data['rows']
        else:
            f = open(cache_filename, 'r')
            self.hosts = json.load(f)

        self.roles = set()
        self.envs = set()
        for host in self.hosts:
            self.roles.update(['%' + role for role in host['roles']])
            self.envs.add('@' + host['chef_environment'])

    def _filter_hosts(self, role=None, env=None):
        logging.debug('filtering role %s env %s', role, env)
        for host in (h for h in self.hosts if role in h['roles']):
            if env == None or env == host['chef_environment']:
                yield host

    def _parse_and_run(self, command):
        m = re.match("^\s*(?P<cmd>\w+)(?:\s+%(?P<role>[-_A-Za-z0-9]+)(?:@(?P<env>[-_A-Za-z0-9]+))?)?\s*(?P<args>.+)*$", command)
        if m:
            filtered_hosts = list(self._filter_hosts(role=m.group('role'), env=m.group('env')))
            if m.group('cmd') == 'hostlist':
                if not m.group('role'):
                    print "USAGE: hostlist %WHAT[@WHERE]"
                    return
                for host in filtered_hosts:
                    print host['hostname']
            elif m.group('cmd') == 'p_exec':
                if not m.group('role') or not m.group('args'):
                    print "USAGE: p_exec %WHAT[@WHERE] COMMAND"
                    return
                cmd = shlex.split("shmux -c '{}' -".format(m.group('args')))
                logging.debug("Executing '%s' on %s", cmd, ','.join( (h['hostname'] for h in filtered_hosts) ))
                try:
                    self._shmux_running = True
                    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                    ret = p.communicate(input='\n'.join((h['hostname'] for h in filtered_hosts)) + '\n' )
                finally:
                    self._shmux_running = False
        else:
            print "Cannot parse command"

    def run(self):
        while True:
            try:
                command = raw_input("> ")
                self._parse_and_run(command)
            except KeyboardInterrupt:
                print "\n"
            except EOFError:
                print "Bye!"
                break

if __name__ == '__main__':
    Butcher().run()
