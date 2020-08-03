#!/usr/bin/env python3

import time
import re
import os
import sys
import configparser
import ipaddress
from datetime import datetime
from bcolor import Base

# Reading config file
config = configparser.ConfigParser()
config.read('watcher.conf')

# Getting sudo password from config
sudo_passwd = config['BASE']['SudoPass']

if len(sudo_passwd) == 0:
  print('Please specify your sudo password in watcher.conf')
  sys.exit(-1)

sleep_time = config['BASE']['TimeBeforeTermination']
if sleep_time == '':
  sleep_time = 60
else:
  sleep_time = int(sleep_time)

# Getting known sources from config
def get_whitelist():
  config.read('watcher.conf')
  config_trusted_ips = config['BASE']['WhiteList'].split(' ')
  return {
    "t_ips": filter(lambda e: re.search('(\d+\.)+0\/\d+', e), config_trusted_ips),
    "t_ranges": filter(lambda e: not re.search('\/', e), config_trusted_ips)
  }

def get_teletype(ip):
  stream = os.popen(f'who | grep "{ip}"')
  connection = stream.read()
  return re.search('pts\/\d+', connection).group(0) if connection != '' else None

def find_pid(tty):
  stream = os.popen(f'ps faux | grep -E "bash$" | grep {tty}')
  res = stream.read()
  pid_match = re.search('(?<=\s)\d+(?=\s+\d\.\d)', res)
  return pid_match.group(0) if pid_match != None else None

def write_to_process(pid):
  print(f'{Base.BOLD + Base.OKGREEN}Writing their goodbye message :){Base.NC}\n')
  dc_msg = """
  \n\tYou should not be here...
  \tTerminating your connection.\n
  """
  stream = os.popen(f' echo {sudo_passwd} | sudo -S bash -c "echo -ne \'{dc_msg}\' > /proc/{pid}/fd/0"')
  stream.close()

def kill_pid(pid):
  stream = os.popen(f' echo {sudo_passwd} | sudo -S kill -9 {pid}')
  print(stream.read())

def kill_if_connected(ip):
  print(f'{Base.WARNING}Found successful connection from {Base.BOLD + ip + Base.NC + Base.WARNING}\nChecking if it is active...{Base.NC}')
  time.sleep(1)
  tty = get_teletype(ip)
  if tty != None:
    print(f'{Base.FAIL}Connection is active with tty {tty}\nWaiting {sleep_time}s before terminating...{Base.NC}')
    time.sleep(sleep_time)
    if check_trusted(ip):
      print(f'{Base.OKGREEN + Base.BOLD + ip + Base.NC + Base.OKGREEN} added themselves to the trusted list.\nAssuming user is legit.{Base.NC}')
      return False
    print(f'{Base.FAIL}Terminating{Base.NC}')
    pid = find_pid(tty)
    if pid == None:
      print(f'{Base.FAIL}No process ID was found.\nSkipping termination but will still block source.{Base.NC}')
      return False
    print(f'{Base.OKGREEN}Found connection process ID: {Base.BOLD + pid + Base.NC}')
    write_to_process(pid)
    time.sleep(1)
    print('Killing process >:)')
    kill_pid(pid)
    print(f'{Base.OKGREEN}\nDone!{Base.NC}')
  else:
    print(f'{Base.OKGREEN}Connection not active{Base.NC}')
  return True

def print_trusted(ip, msg):
  print(f'{Base.OKGREEN + Base.BOLD + ip + Base.NC + Base.OKGREEN} is trusted: {msg + Base.NC}')

def check_trusted(ip):
  if ipaddress.ip_address(ip).is_private:
    print_trusted(ip, 'local ip')
    return True
  else:
    ts = get_whitelist()
    for address in ts['t_ips']:
      if ip == address:
        print_trusted(ip, 'whitelisted')
        return True
    for ip_range in ts['t_ranges']:
      if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
        print_trusted(ip, f'exists in whitelisted range {Base.Bold + ip_range}')
        return True
    return False
