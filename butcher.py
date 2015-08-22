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
import argparse
import getpass
import traceback

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
            string = tokens[1].split(',')[-1]       #comma-separated list of hosts/roles
            if string.find('@') > 0:
                role = string.split('@')[0]
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

    def __init__(self, cached=True):
        self.commands = ['exec', 'p_exec', 'hostlist', 'reload', 'threads', 'user']
        self.usage = {
                'reload': 'reload',
                'user': 'user USER',
                'threads': 'threads THREADS',
                'hostlist': 'hostlist %ROLE[@ENV]|HOST[,%ROLE[@ENV]|HOST...]',
                'p_exec': 'p_exec %ROLE[@ENV]|HOST[,%ROLE[@ENV]|HOST...] COMMAND',
                'exec': 'exec %ROLE[@ENV]|HOST[,%ROLE[@ENV]|HOST...] COMMAND'
                }
        self.user = getpass.getuser()
        self.threads=50
        self._shmux_running = False
        self._load_hosts(cached=cached)
        readline.parse_and_bind('tab: complete')
        readline.set_completer(CommandCompleter(commands=self.commands, roles=self.roles, envs=self.envs).complete)
        readline.set_completer_delims(' ,')
        histfile=os.path.join(BUTCHER_DIR, 'history')
        try:
            readline.read_history_file(histfile)
        except IOError:
            pass
        atexit.register(readline.write_history_file, histfile)
        signal.signal(signal.SIGINT, self._sigint())


    def _get_ps(self):
        return "{} > ".format(self.user)

    def _sigint(self):
        def __handler(signal, frame):
            if self._shmux_running:
                pass
            else:
                raise KeyboardInterrupt
        return __handler

    def _load_hosts(self, env = None, cached=True):
        cache_filename = os.path.join(BUTCHER_DIR, 'cache.json')
        self.hosts = []
        if not cached or not os.path.isfile(cache_filename):
            if not os.path.isdir(BUTCHER_DIR):
                os.mkdir(BUTCHER_DIR)
            cmd = shlex.split("knife search node '*' -a roles -a hostname -a chef_environment -F json")
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            data = json.load(p.stdout)
            print "Loaded {} hosts".format(data['results'])

            for host in data['rows']:
                name = host.keys()[0]
                self.hosts.append(host[name])
            f = open(cache_filename, 'w')
            json.dump(self.hosts, f)
            f.close()
        else:
            f = open(cache_filename, 'r')
            self.hosts = json.load(f)

        self.roles = set()
        self.envs = set()
        for host in self.hosts:
            logging.debug("Processing host %s", host)
            self.roles.update(['%' + role for role in host['roles']])
            self.envs.add('@' + host['chef_environment'])

    def _filter_hosts(self, string):
        for token in string.split(','):
            m = re.search('^%([-_A-Z-a-z0-9]+)(?:@([-_A-Za-z0-9]+))?$', token)
            if m:
                # treat token as %role[@env]
                (role, env) = m.groups()
                logging.debug('filtering role %s env %s', role, env)
                for host in (h for h in self.hosts if role in h['roles']):
                    if env == None or env == host['chef_environment']:
                        yield host['hostname']
            else:
                # treat token as host
                yield token

    def _parse_and_run(self, command):
        m = re.match("^\s*(?P<cmd>\w+)(?:\s+%(?P<role>[-_A-Za-z0-9]+)(?:@(?P<env>[-_A-Za-z0-9]+))?)?\s*(?P<args>.+)*$", command)
        # remove extra spaces
        # command = re.sub("^\s*(\w+)\s+", "\g<1> ", command)
        tokens = shlex.split(command)
        cmd = tokens[0]
        if cmd not in self.commands:
            print "Available commands:\n{}".format(', '.join(self.commands))
            return

        try:
            if cmd == 'reload':
                self._load_hosts(cached=False)
                return
            if cmd == 'threads':
                self.threads = int(tokens[1])
                return
            if cmd == 'user':
                self.user = tokens[1]
                return
            if cmd in ('hostlist', 'exec', 'p_exec'):
                filtered_hosts = set(self._filter_hosts(tokens[1]))
                if cmd == 'hostlist':
                    for host in filtered_hosts:
                        print host
                    return

                if cmd == 'exec':
                    threads = 1
                elif cmd == 'p_exec':
                    threads = self.threads

                if not tokens[2:]:
                    raise Exception("Specify command to execute")

                remote_cmd = ' '.join(tokens[2:])
                shmux_cmd = shlex.split("shmux -B -M{} -c '{}' -".format(threads, remote_cmd))

                logging.debug("Executing '%s' on %s", shmux_cmd, ','.join(filtered_hosts))
                try:
                    self._shmux_running = True
                    os.environ['SHMUX_SSH_OPTS'] = '-l {}'.format(self.user)
                    p = subprocess.Popen(shmux_cmd, stdin=subprocess.PIPE)
                    ret = p.communicate(input='\n'.join(filtered_hosts) + '\n' )
                except OSError as e:
                    print "Cannot launch shmux: {}".format(e)
                finally:
                    self._shmux_running = False
                return
        except Exception as e:
            logging.debug("Got exception %s, %s", sys.exc_info(), traceback.extract_tb(sys.exc_traceback))
            print "USAGE:\n\t{}".format(self.usage[cmd])
            return


    def run(self):
        while True:
            try:
                command = raw_input(self._get_ps())
                self._parse_and_run(command)
            except KeyboardInterrupt:
                print "\n"
            except EOFError:
                print "Bye!"
                break

if __name__ == '__main__':
    p = argparse.ArgumentParser(description="Butcher, the shmux shell")
    p.add_argument('-c', '--cached', action='store_true', default=False)
    args = p.parse_args()
    Butcher(cached=args.cached).run()
