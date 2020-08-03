#!/usr/bin/env python3

import subprocess
import os
import select
import sys
import configparser

import handler
from bcolor import Base

config = configparser.ConfigParser()
config.read('watcher.conf')

ssh_log_file = config['FILE']['LogPath']
if ssh_log_file == '':
  ssh_log_file = '/var/log/auth.log'

# check if user has ufw installed
def check_for_ufw():
  if config['BASE'].getboolean('DevMode'):
    return
  stream = os.popen('whereis ufw')
  res = stream.read()
  if len(res) < 6:
    print('Cannot find package ufw on the system, please install it\nExiting')
    sys.exit(-1)

# checks whole auth log for login attempts
def run_check_all():
  print(f"{Base.OKBLUE}\t\t############ Running in All mode ############{Base.NC}")
  with open(ssh_log_file) as auth:
    for line in auth:
      handler.process_line(line, False)
  handler.reload_ufw()

# tails auth log file for new login attempts
def run_tail ():
  print(f"{Base.OKBLUE}\t\t############ Running in Tail mode ############{Base.NC}")
  f = subprocess.Popen(['tail', '-n0',  '-f', ssh_log_file],\
      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  p = select.poll()
  p.register(f.stdout)

  while True:
    if p.poll(1):
      line = str(f.stdout.readline())
      handler.process_line(line, True)

# print help message
def print_help():
  print("""
  A script to block all unknown addresses that has tried to connect via ssh to your device.
  When an unknown address is found, the script blocks the whole address range of that IP.

  Note: the script needs ufw to be installed on the system

  Usage:
    -t : Tail mode - tails the /var/log/auth.log file for new entries
    -a : All mode - goes through all of /var/log/auth.log
  """)
  sys.exit(0)

def print_header():
  print(f'{Base.HEADER + Base.BOLD}\n\t   ____ ____ __ __  _      __ ___  ______ _____ __ __ ____ ___ ')
  print('\t  / __// __// // / | | /| / // _ |/_  __// ___// // // __// _ \\')
  print('\t _\ \ _\ \ / _  /  | |/ |/ // __ | / /  / /__ / _  // _/ / , _/')
  print(f'\t/___//___//_//_/   |__/|__//_/ |_|/_/   \___//_//_//___//_/|_| {Base.NC}\n')

if len(sys.argv) > 2:
  print("Too many arguments specified\nUse -h for help")
else:

  print_header()
  arg = sys.argv[len(sys.argv) - 1]
  if arg == '-h':
    print_help()
  else:
    check_for_ufw()
    try:
      if arg == '-a':
        run_check_all()
      else:
        run_tail()
    except KeyboardInterrupt as e:
      handler.reload_ufw()
      sys.exit()
