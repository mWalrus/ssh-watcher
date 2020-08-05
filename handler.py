#!/usr/bin/env python3

import time
import subprocess
import select
import re
import os
import sys
import configparser
from datetime import datetime
import terminator

from bcolor import Base

config = configparser.ConfigParser()
config.read('watcher.conf')

sudo_passwd = config['BASE']['SudoPass']

if len(sudo_passwd) == 0:
  print('Please specify your sudo password in watcher.conf')
  sys.exit(-1)

def get_blocked_addresses():
  path = './blocklist.list'
  if not os.path.exists(path):
    temp = open(path, 'w+')
    temp.close()
  f = open(path)
  content = f.read()
  return content.split('\n')

blocked_addresses = get_blocked_addresses()
updated_firewall = False

# updating list of blocked addresses
def update_blocklist(ip):
  blocked_addresses.append(ip)
  f = open('./blocklist.list', 'w')
  f.write('\n'.join(blocked_addresses))
  f.close()

# block ip address in ufw
def block_ip_address(ip):
  if not config['BASE'].getboolean('DevMode'):
    # space at beginning of command to prevent password from being saved in plain text in bash history
    print(f"{Base.FAIL}Blocking host IP {Base.BOLD + ip + Base.NC}")
    stream = os.popen(f' echo {sudo_passwd} | sudo -S ufw insert 1 deny from {ip} to any')
    res = stream.read()
    print(res)
    updated_firewall = True
    update_blocklist(ip)
    print(f"{Base.OKGREEN }Added {Base.BOLD + ip + Base.NC + Base.OKGREEN} to blocklist {Base.NC}")

def reload_ufw():
  if config['BASE'].getboolean('DevMode'): return
  if not updated_firewall:
    print(f'\n\n{Base.WARNING}No firewall changes made\nSkipping firewall reload{Base.NC}')
    return
  print(f'\n\n{Base.WARNING}Reloading firewall{Base.NC}')
  stream = os.popen(f' echo {sudo_passwd} | sudo -S ufw reload')
  res = stream.read()
  print(res)

def get_connection_details(line, match):
  return {
    "usr": match.group(0),
    "ip_addr": re.search('((\d+\.)+\d+)', line).group(0),
    "date": re.search('[A-Z]\w{2}\s{1,2}\d{1,2}', line).group(0),
    "time": re.search('(\d{2}:\d{2}:\d{2})', line).group(0),
  }

def check_blocklist(ip, tail_mode):
  ip_exists = False
  for r in blocked_addresses:
    if r == ip: ip_exists = True
  
  if ip_exists:
    print(f"{Base.OKBLUE}IP {Base.BOLD + ip + Base.NC + Base.OKBLUE} is already blocked!\nSkipping{Base.NC}")
  else:
    block_ip_address(ip)
    if tail_mode: reload_ufw()

def print_entry(ip, usr, date, time, msg):
  print(f"{Base.BOLD + ip + Base.NC + ' ' +  msg + ' ' + Base.BOLD + usr + Base.NC} at {date + ' ' + time}")

def handle_new_entry(line, match, entry_type, tail_mode):
  conn_info = get_connection_details(line, match)
  ip = conn_info['ip_addr']
  usr = conn_info['usr']
  date = conn_info['date']
  time = conn_info['time']

  print('\n\n')
  if entry_type == 0:
    print_entry(ip, usr, date, time, 'tried to connect as')
    check_blocklist(conn_info['ip_addr'], tail_mode)
  elif entry_type == 1:
    print_entry(ip, usr, date, time, 'sucessfully connected as')
    if not terminator.check_trusted(ip) and terminator.kill_if_connected(ip):
      check_blocklist(ip, tail_mode)
  elif entry_type == 2:
    print_entry(ip, usr, date, time, 'failed password for')
    if not terminator.check_trusted(ip):
      check_blocklist(ip, tail_mode)

# check line for matching information
def process_line(line, tail_mode):
  searches = [re.search('(?<=\sfor\sinvalid\suser\s)\w+', line), re.search('(?<=Accepted\spassword\sfor\s)\w+', line), re.search('(?<=Failed\spassword\sfor\s)\w+', line)]
  index = [i for i,v in enumerate(searches) if v != None]
  if len(index) > 0: handle_new_entry(line, searches[index[0]], index[0], tail_mode)
