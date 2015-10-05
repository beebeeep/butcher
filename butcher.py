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

    def __init__(self, commands=[], clusters=[], regions=[]):
        self.commands = sorted(commands)
        self.clusters = sorted(['%' + x for x in clusters])
        self.regions = sorted(regions)
        self.variables = sorted(['region', 'user', 'threads'])
        return

    def complete(self, text, state):
        response = None
        tokens = shlex.split(readline.get_line_buffer())
        opts = []
        logging.debug("text '%s', state %s, buffer '%s', tokens %s", text, state, readline.get_line_buffer(), tokens)
        if not tokens or (len(tokens) == 1 and len(text)):              # only one token and it's not completed
            opts = self.commands
        else:
            if 'exec' in tokens[0]:                      # one of exec commands
                if len(tokens) >= 2:
                    string = tokens[1].split(',')[-1]       # comma-separated list of hosts/clusters
                    if '@' in string:
                        cluster = string.split('@')[0]
                        opts = [cluster + '@' + e for e in self.regions]
                    else:
                        opts = self.clusters
                else:
                    opts = self.clusters
            elif tokens[0] == 'region':
                opts = self.regions
            elif tokens[0] == 'unset':
                opts = self.variables

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
        self.commands = ['exec', 'p_exec', 'hostlist', 'reload', 'threads', 'user', 'region', 'unset']
        self.usage = {
                'reload': 'reload',
                'user': 'user USER',
                'unset': 'unset VARIABLE',
                'region': 'region REGION (NONE to reset)',
                'threads': 'threads THREADS',
                'hostlist': 'hostlist %CLUSTER[@REGION]|HOST[,%CLUSTER[@REGION]|HOST...]',
                'p_exec': 'p_exec %CLUSTER[@REGION]|HOST[,%CLUSTER[@REGION]|HOST...] COMMAND',
                'exec': 'exec %CLUSTER[@REGION]|HOST[,%CLUSTER[@REGION]|HOST...] COMMAND'
                }
        self.user = getpass.getuser()
        self.threads=50
        self.region = None
        self._shmux_running = False

        self._load_hosts(cached=cached)

        readline.parse_and_bind('tab: complete')
        readline.set_completer(CommandCompleter(commands=self.commands, clusters=self.clusters, regions=self.regions).complete)
        readline.set_completer_delims(' ,')
        histfile=os.path.join(BUTCHER_DIR, 'history')
        try:
            readline.read_history_file(histfile)
        except IOError:
            pass
        atexit.register(readline.write_history_file, histfile)
        signal.signal(signal.SIGINT, self._sigint())

    def _get_ps(self):
        return "<{}> {} > ".format((self.region or 'ALL'), self.user)

    def _sigint(self):
        def __handler(signal, frame):
            if self._shmux_running:
                pass
            else:
                raise KeyboardInterrupt
        return __handler

    def _load_hosts(self, cached=True):
        cache_filename = os.path.join(BUTCHER_DIR, 'cache.json')
        self.hosts = []
        if not cached or not os.path.isfile(cache_filename):
            if not os.path.isdir(BUTCHER_DIR):
                os.mkdir(BUTCHER_DIR)
            for env in ['pre', 'qa', 'live']:
                print "Loading env {}...".format(env)
                cmd = shlex.split("knife search node '*' -a roles -a hostname -a chef_environment -F json -c ~/.chef/knife-{}.rb".format(env))
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
                data = json.load(p.stdout)

                for host in data['rows']:
                    name = host.keys()[0]
                    host[name]['clusters'] = host[name]['roles']
                    host[name]['region'] = host[name]['chef_environment']
                    del(host[name]['roles'])
                    del(host[name]['chef_environment'])
                    self.hosts.append(host[name])
            f = open(cache_filename, 'w')
            json.dump(self.hosts, f)
            f.close()
        else:
            f = open(cache_filename, 'r')
            self.hosts = json.load(f)

        self.clusters = set()
        self.regions = set()
        for host in self.hosts:
            logging.debug("Processing host %s", host)
            self.clusters.update(host['clusters'])
            self.regions.add(host['region'])
        print "Loaded {} hosts, {} clusters in {} regions".format(len(self.hosts), len(self.clusters), len(self.regions))

    def _filter_hosts(self, string):
        if not string:
            # list all hosts in current region
            for host in (h for h in self.hosts if not self.region or h['region'] == self.region):
                yield host['hostname']

        for token in string.split(','):
            m = re.search('^%([-_A-Z-a-z0-9]+)(?:@([-_A-Za-z0-9]+))?$', token)
            if m:
                # treat token as %cluster[@region]
                (cluster, region) = m.groups()
                if not region and self.region:
                    region = self.region
                logging.debug('filtering cluster %s region %s', cluster, region)
                for host in (h for h in self.hosts if cluster in h['clusters']):
                    if region == None or region == host['region']:
                        yield host['hostname']
            else:
                # treat token as host
                yield token

    def _parse_and_run(self, command):
        tokens = shlex.split(command)
        if not tokens:
            return

        cmd = tokens[0]
        if cmd not in self.commands:
            print "Available commands:\n{}".format(', '.join(self.commands))
            return

        try:
            if cmd == 'reload':
                self._load_hosts(cached=False)
                return
            if cmd == 'threads':
                if len(tokens) == 1:
                    print "threads = {}".format(self.threads)
                    return
                self.threads = int(tokens[1])
                return
            if cmd == 'region':
                if len(tokens) == 1:
                    print "region = {}".format(self.region)
                    return
                self.region = tokens[1]
                if tokens[1] == 'NONE':
                    self.region = None
                return
            if cmd == 'unset':
                var = tokens[1]
                if var == 'region':
                    self.region = None
                elif var == 'user':
                    self.user = getpass.getuser()
                elif var == 'threads':
                    self.threads = 50
                return
            if cmd == 'user':
                if len(tokens) == 1:
                    print "user = {}".format(self.user)
                self.user = tokens[1]
                return
            if cmd in ('hostlist', 'exec', 'p_exec'):
                if cmd == 'hostlist':
                    if len(tokens) == 1:
                       hoststring = ''
                    elif len(tokens) == 2:
                        hoststring = tokens[1]
                    else:
                        raise Exception()

                    for host in set(self._filter_hosts(hoststring)):
                        print host
                    return

                filtered_hosts = set(self._filter_hosts(tokens[1]))
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
