# SSH Watcher

A small script to monitor incoming SSH connections.

# Requirements

To be able to run this script you will need to install [ufw](https://wiki.archlinux.org/index.php/Uncomplicated_Firewall "Uncomplicated Firewall").


**IMPORTANT**: If you are installing ufw for the first time and
you are doing it over an SSH connection you need add rules to allow
SSH connections. Otherwise your connection will be terminated and
you wont be able to log in anymore.

# Features

## Trusting and blocking
This script is capable of distinguishing between local addresses and public addresses.
If a local address connects to the machine running this script the script will trust it.
If a public address connects then the script will compare the address to the entries
in the whitelist and if a match is found the address will be trusted, otherwise the
address will be blocked and put in the blocklist.list file.

## Successful connections
When a successful connection is detected the script will first check if the ip is trusted.
If the address is not then the script checks if the connection is active. If the connection
is active the script will try to terminate that connection.

## Active connection termination
When an active connection is found the script will try to find the current connection's process id.
This process id can be written to and also terminated. When everything has been found to go through
with the termination of the active connection the script will write a message to their terminal and
then kill the process that the connection.

# Modes

### All mode

`./watcher.py -a`  
All mode goes through the entire ssh auth.log file and checks connection attempts.

### Tail mode

`./watcher.py -t` or just `./watcher.py`  
Tail mode tails the log file and handles all the new incoming connection attemps made after the script is started.

## Setup

1. Clone project:  
`git clone https://github.com/mWalrus/ssh-watcher.git`
2. Enter project directory:  
`cd ssh-watcher`
3. Create config file:  
`touch watcher.conf`
4. Copy and paste this in watcher.conf:  
```
########################################################
#                       SSH WATCHER                    #
#                    Configuration File                 #
########################################################
[BASE]
# Sudo password to insert rules into the firewall
SudoPass=

# Separate addresses with space.
# You can also specify IP ranges.
# Local addresses and address spaces will be detected
# by the script so there is no need to specify those here
TrustedIPs=

# This decides how many seconds the script waits before
# terminating an active connection.
# This is to allow for a knowing user to connect and
# add their ip to the TrustedIPs list above.
# If empty the timeout will default to 60 seconds.
TimeBeforeTermination=

# Will prevent updates to ufw and blocklist if true
DevMode=False

[FILE]
# Define custom path to log file if you have a sample
# file during development for example.
# Will default to /var/log/auth.log if left empty
LogPath=
```
5. fill in sudo password in wacther.conf

## Running the script
Nodejs has a package called [pm2](https://pm2.keymetrics.io/ "Advanced, production process manager") which can be
used to run this script as a background process. While in the project folder you can start a process running the
script with a single command:  
`pm2 start watcher.py -l watcher.log --interpreter python3`
The `-l watcher.log` specifies that pm2 should log the process' output to the file watcher.log (you don't have to create the file before hand)
The `--interpreter python3` is used to make sure that the correct interpreter is used.
