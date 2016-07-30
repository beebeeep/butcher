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
import sqlite3

logging.basicConfig(filename='/tmp/butcher.log', level=logging.DEBUG)
BUTCHER_DIR = os.path.join(os.environ['HOME'], '.butcher')


class CommandCompleter(object):

    def __init__(self, commands, variables, db):
        self.commands = sorted(commands)
        self.variables = sorted(variables)
        self.db = db

    def _get_envs(self):
        c = self.db.cursor()
        return list(x[0] for x in c.execute("SELECT * FROM environments"))

    def _get_roles(self):
        c = self.db.cursor()
        return list('%' + x[0] for x in c.execute("SELECT * FROM roles"))

    def _get_regions(self):
        c = self.db.cursor()
        return list(x[0] for x in c.execute("SELECT * FROM regions"))

    def _get_hosts(self):
        c = self.db.cursor()
        return list(x[0] for x in c.execute("SELECT * FROM hosts"))

    def complete(self, text, state):
        response = None
        tokens = shlex.split(readline.get_line_buffer())
        opts = []
        logging.debug("text '%s', state %s, buffer '%s', tokens %s", text, state, readline.get_line_buffer(), tokens)
        if not tokens or (len(tokens) == 1 and len(text)):              # only one token and it's not completed
            opts = self.commands
        else:
            if 'exec' in tokens[0] or 'hostlist' in tokens[0]:
                if len(tokens) >= 2:
                    string = tokens[1].split(',')[-1]       # comma-separated list of hosts/roles
                    if '@' in string:
                        role = string.split('@')[0]
                        opts = [role + '@' + e for e in self._get_regions()]
                    else:
                        if string.startswith('%'):
                            opts = self._get_roles()
                        else:
                            opts = self._get_hosts()
                else:
                    opts = self._get_roles()
            elif tokens[0] == 'region':
                opts = self._get_regions()
            elif tokens[0] == 'env':
                opts = self._get_envs()
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
        self.commands = ['exec', 'p_exec', 'hostlist', 'reload', 'threads', 'user', 'env', 'region', 'unset']
        self.variables = ['environment', 'region', 'user', 'threads']
        self.usage = {
                'reload': 'reload',
                'user': 'user USER',
                'unset': 'unset VARIABLE',
                'env': 'env ENV',
                'region': 'region REGION (NONE to reset)',
                'threads': 'threads THREADS',
                'hostlist': 'hostlist %ROLE[@REGION]|HOST[,%ROLE[@REGION]|HOST...]',
                'p_exec': 'p_exec %ROLE[@REGION]|HOST[,%ROLE[@REGION]|HOST...] COMMAND',
                'exec': 'exec %ROLE[@REGION]|HOST[,%ROLE[@REGION]|HOST...] COMMAND'
                }
        self.user = getpass.getuser()
        self.threads=50
        self.region = None
        self.environments = ['pre', 'qa', 'live']
        #self.environments = ['pre']
        self.environment = self.environments[0]
        self._shmux_running = False

        if not os.path.isdir(BUTCHER_DIR):
            os.mkdir(BUTCHER_DIR)

        self.db = sqlite3.connect(os.path.join(BUTCHER_DIR, 'butcher.db'))

        self._load_hosts(cached=cached)

        readline.parse_and_bind('tab: complete')
        readline.set_completer(CommandCompleter(commands=self.commands, variables=self.variables, db=self.db).complete)
        readline.set_completer_delims(' ,')
        histfile=os.path.join(BUTCHER_DIR, 'history')
        try:
            readline.read_history_file(histfile)
        except IOError:
            pass
        atexit.register(readline.write_history_file, histfile)
        atexit.register(self.db.close)
        signal.signal(signal.SIGINT, self._sigint())

    def _get_ps(self):
        if 'pre' in self.environment.lower():
            ec = "\033[0;32m"
        elif 'qa' in self.environment.lower():
            ec = "\033[0;33m"
        else:
            ec = "\033[0;31m"
        rc = "\033[0;36m"
        return "{ec}{}{e}@{rc}{}{e} {} > ".format(self.environment, (self.region or 'ALL'), self.user, ec=ec, rc=rc, e="\033[0m")

    def _sigint(self):
        def __handler(signal, frame):
            if self._shmux_running:
                pass
            else:
                raise KeyboardInterrupt
        return __handler

    @staticmethod
    def _knife(chef, cmd):
        cmd = shlex.split("knife {} -c ~/.chef/knife-{}.rb".format(cmd, chef))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        return p.stdout

    def _update_hosts(self, chef, query):
        data = json.load(self._knife(chef, "search node '{}' -a roles -a hostname -a chef_environment -F json".format(query)))
        cur = self.db.cursor()
        for host in data['rows']:
            hostname = host.keys()[0]
            host = host[host.keys()[0]]
            cur.execute('INSERT OR IGNORE INTO regions VALUES (?)', (host['chef_environment'],))
            cur.execute('INSERT OR REPLACE INTO hosts VALUES (?, ?, ?)', (hostname, host['chef_environment'], chef))
            cur.execute("DELETE FROM runlists WHERE host=? AND role NOT IN({})".format(','.join("'" + x + "'" for x in host['roles'])), (hostname,))
            for role in host['roles']:
                cur.execute('INSERT OR IGNORE INTO roles VALUES (?)', (role,))
                cur.execute('INSERT OR IGNORE INTO runlists VALUES(null, ?, ?)', (hostname, role))
            host['roles'] = host['roles']
            host['region'] = host['chef_environment']
            del(host['roles'])
            del(host['chef_environment'])
            self.hosts.append(host)
        self.db.commit()

    def _load_hosts(self, cached=True):
        cache_filename = os.path.join(BUTCHER_DIR, 'cache.json')
        self.hosts = []
        cur = self.db.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS environments (name TEXT pimary key unique)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS regions (name TEXT PRIMARY KEY unique)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS roles (name TEXT PRIMARY KEY unique)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS hosts(name TEXT PRIMARY KEY, region TEXT, environment TEXT, FOREIGN KEY (environment) REFERENCES environments(name), FOREIGN KEY (region) REFERENCES regions(name) )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS runlists(id INTEGER PRIMARY KEY, host TEXT, role TEXT,
                FOREIGN KEY (host) REFERENCES hosts(name) ON DELETE CASCADE, FOREIGN KEY (role) REFERENCES roles(name) ON DELETE CASCADE)""")
        cur.execute("""CREATE INDEX IF NOT EXISTS runlist_host ON runlists(host)""")
        cur.execute("""CREATE INDEX IF NOT EXISTS runlist_role ON runlists(role)""")
        cur.execute("""CREATE UNIQUE INDEX IF NOT EXISTS runlist_entry ON runlists(host,role)""")
        self.db.commit()

        cur.executemany('INSERT OR IGNORE INTO environments VALUES (?)', ((x,) for x in self.environments))

        if not cached:
            for chef in self.environments:
                print "Loading chef {}...".format(chef)
                self._update_hosts(chef, '*')

        hosts = cur.execute("SELECT COUNT(*) from hosts").fetchone()[0]
        regions = cur.execute("SELECT COUNT(*) from regions").fetchone()[0]
        roles = cur.execute("SELECT COUNT(*) from roles").fetchone()[0]
        print "Loaded {} environments: {} hosts and {} roles in {} regions".format(len(self.environments), hosts, roles, regions)

    def _filter_hosts(self, string):
        cur = self.db.cursor()
        if not string:
            # list all hosts in current region & env
            for host in cur.execute(
                    "SELECT name FROM hosts WHERE region LIKE ? AND environment LIKE ?", ( (self.region or '%'), (self.environment or '%'))):
                yield host[0]
        else:
            for token in string.split(','):
                m = re.search('^%([*-_A-Z-a-z0-9]+)(?:@([-_A-Za-z0-9]+))?$', token)
                if m:
                    # treat token as %role[@region]
                    (role, region) = m.groups()
                    role = role.replace('*', '%')
                    if not region and self.region:
                        region = self.region
                    logging.debug('filtering role %s region %s', role, region)
                    for host in cur.execute(
                        """SELECT runlists.host FROM runlists INNER JOIN hosts ON hosts.name=runlists.host
                            WHERE runlists.role LIKE ? AND hosts.region LIKE ? AND hosts.environment=?""", (role, (region or '%'), self.environment)):
                        yield host[0]
                else:
                    # treat token as host
                    for host in cur.execute("SELECT name FROM hosts WHERE name LIKE ?", (token, )):
                        yield host[0]

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
            elif cmd == 'threads':
                if len(tokens) == 1:
                    print "threads = {}".format(self.threads)
                else:
                    self.threads = int(tokens[1])
            elif cmd == 'env':
                if len(tokens) == 1:
                    print "env = {}".format(self.environment)
                else:
                    self.environment = tokens[1]
            elif cmd == 'region':
                if len(tokens) == 1:
                    print "region = {}".format(self.region)
                    return
                else:
                    self.region = tokens[1]
                    if tokens[1] == 'NONE':
                        self.region = None
            elif cmd == 'unset':
                var = tokens[1]
                if var == 'region':
                    self.region = None
                elif var == 'user':
                    self.user = getpass.getuser()
                elif var == 'threads':
                    self.threads = 50
            elif cmd == 'user':
                if len(tokens) == 1:
                    print "user = {}".format(self.user)
                else:
                    self.user = tokens[1]
            elif cmd in ('hostlist', 'exec', 'p_exec'):
                if cmd == 'hostlist':
                    if len(tokens) == 1:
                       hoststring = ''
                    elif len(tokens) == 2:
                        hoststring = tokens[1]
                    else:
                        raise Exception()

                    i = 0
                    for host in set(self._filter_hosts(hoststring)):
                        i += 1
                        print host
                    print "\n{} host{} total".format(i, 's' if i > 1 else '')
                else:
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
