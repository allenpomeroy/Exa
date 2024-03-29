#!/usr/bin/python3
#
# notable-poll.py
#
# Uses Search API calls to an Exabeam NewScale(tm) tenant
# to find Notable User and Notable Asset notification events.
# Keeps track of notable sessions found and sends any new
# sessions discovered since the last poll to a configurable
# number of syslog TLS destinations.
#
# Currently only polls a single Exabeam tenant per configuration
# file, however allows a variable number of syslog TLS
# destinations.  No TLS authentication is performed, only 
# encryption of payload. State files are maintained to track
# unique sessions encountered and optionally a blacklist of 
# user or assets to ignore.
#
# All configuration is done through a configuration file
# "notable-poll.conf" in INI format.
#
# Typical use in crontab:
# m h  dom mon dow   command
#0,15,30,45 * * * * cd /home/exabeam/notable-poll; /home/exabeam/notable-poll/notable-poll.py >/home/exabeam/notable-poll/notable-poll.log 2>&1
#
# 
# Copyright 2023, Allen Pomeroy - MIT license
#
# v1.7
# - add configurable lookbacktime for poll
# - add error trapping for queries and syslog setup
# - add ability to specify variable number of syslog dest
# - add blacklist to exclude arbitrary users or assets
# - add fourth syslog dest for monitoring
# - add multiple syslog destinations for BB

# MIT License
# Copyright (c) 2022-2023 allenpomeroy and contributors
# github.com/allenpomeroy/Exa/API/notable-poll.py
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# ===============================================================
# NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE
# ===============================================================
# This script is NOT supported or endorsed by Exabeam in any way.
# It is only provided to illustrate an example of what may be
# accomplished with the Exabeam NewScale Security Operations
# Platform APIs.
# ===============================================================
# Please DO NOT contact Exabeam customer success with any questions
# or requests for assistance.  You may contact the author however
# only best efforts can be made to respond or accomodate change
# requests.
# ===============================================================


# =====
# imports and packages
import requests
import time
import json
import syslog
import os
import datetime
import socket
import logging
import logging.handlers
import ssl
import configparser
import fcntl

# =====
# read configuration items from config file in current working directory
config = configparser.ConfigParser()
config.read('notable-poll.conf')

#
# get config items
num_destinations = int(config.get('syslogdata', 'num_destinations'))
#
lookbacktime = config.get('exabeam', 'lookbacktime')
exaauthurl = config.get('exabeam', 'authurl')
exasearchurl = config.get('exabeam', 'searchurl')
envname = config.get('exabeam', 'envname')
exaauthkey = config.get('exabeam', 'authkey')
exaauthsecret = config.get('exabeam', 'authsecret')
#
debuglevel = int(config.get('general', 'debug'))
sessionstatefile = config.get('general', 'sessionstatefile')
lockfile = config.get('general', 'lockfile')
logfile = config.get('general', 'logfile')
blacklistfile = config.get('general', 'blacklistfile')

# =====
# ensure we are not already running - get lock file

# try to acquire the lock file
try:
    lock_file = open(lockfile, "w")
    fcntl.lockf(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if (debuglevel > 0):
      print('INFO: ' + __file__ + ' starting, lock successfully acquired')
except IOError as e:
    print("ERROR: Another instance of the program is already running or failed to get lock file.")
    exit(1)


# =====
# setup syslog destinations
class SSLSysLogHandler(logging.handlers.SysLogHandler):
    def __init__(self, host, port, ssl_context):
        super(SSLSysLogHandler, self).__init__(address=(host, port))
        self.ssl_context = ssl_context

    def makeSocket(self, timeout=1):
        sock = super().makeSocket(timeout=timeout)
        if self.ssl_context:
            sock = self.ssl_context.wrap_socket(sock)
        return sock

    def emit(self, record):
        """
        Emit a record.

        Send the record to the syslog server using UDP or TCP (depending
        on the socket being used by the handler) and SSL/TLS if a context
        is provided.
        """
        msg = self.format(record) + '\000'
        try:
            if self.sock is None:
                self.createSocket()
            self.sock.sendall(msg.encode('utf-8'))
        except (KeyboardInterrupt, SystemExit):
            raise
        except ConnectionRefusedError as e:
            # handle ConnectionRefusedError
            print(f"WARNING: Connection refused for syslog destination {self.host}:{self.port}: {e}")
        except Exception as e:
            print(f"ERROR: Error encountered with syslog destination {self.host}:{self.port}: {e}")
            # handle other exceptions
            self.handleError(record)


# =====
# setup common syslog destination features

# create an SSL context
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# create a logger instance
logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)

# set the syslog format
formatter = logging.Formatter('%(asctime)s %(name)s: %(levelname)s %(message)s ', datefmt='%b %d %H:%M:%S\n')

# =====
# setup syslog destinations

# loop through each syslog destination and configure logging to
# send syslog over TCP with the wrapped socket
for i in range(1, num_destinations+1):
    host = config.get('syslogdata', f'syslogdatahost{i}')
    port = int(config.get('syslogdata', f'syslogdataport{i}'))

    try:
        # create a TCP socket for syslog destination i
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        # wrap the socket with SSL/TLS using the context
        wrapped_sock = ssl_context.wrap_socket(sock)
        # configure logging to send syslog over TCP with the wrapped socket
        syslog_handler = SSLSysLogHandler(host, port, ssl_context)
        syslog_handler.sock = wrapped_sock
        syslog_handler.setFormatter(formatter)
        logger.addHandler(syslog_handler)
        if (debuglevel > 1):
          print(f"INFO: Connection setup for syslog destination {host}:{port}")
    except ConnectionRefusedError as e:
        # handle ConnectionRefusedError during setup
        print(f"WARNING: Connection refused during setup of syslog destination {host}:{port}: {e}")
    except Exception as e:
        # handle other exceptions
        print(f"ERROR: Error encountered during setup of syslog destination {host}:{port}: {e}")


# =====
# log our startup
msg = "INFO: Starting query of " + envname + " .. heartbeat"
print(msg)
logger.info(msg)


# =====
# read blacklist if any - prevents any specified user or asset
# from being sent to any syslog destination
# ensure file exists - create blank if not
open(blacklistfile, 'a').close()
# load the blacklist from the file
blacklist = set()
try:
    with open(blacklistfile, 'r') as f:
        for line in f:
            userorasset = line.strip()
            if userorasset:
                blacklist.add(userorasset)
except FileNotFoundError:
    pass


# =====
# setup datetime strings - query back last x time specified by lookbacktime
now = datetime.datetime.now()

lookbackparts = lookbacktime.split("=")
timeunit = lookbackparts[0].strip(' "')
timevalue = int(lookbackparts[1].strip(' "'))

deltaString = f"datetime.timedelta({timeunit}={timevalue})"
deltaTime = eval(deltaString)
pastTime = now - deltaTime

startTime = pastTime.isoformat() + 'Z'
endTime = now.isoformat() + 'Z'
if (debuglevel > 0):
  print("DEBUG: Query startTime: " + str(startTime) + " endTime: " + str(endTime))


# =====
# use api key and secret to generate token

# contact Exabeam tenant administrator or local Exabeam contact to obtain
# correct authorization and query URLs.  these are specific to region
# customer tenant is located within

# exaauthurl, authkey and authsecret are read from config file
payload = {
    "grant_type": "client_credentials",
    "client_id": exaauthkey,
    "client_secret": exaauthsecret
}
headers = {
    "accept": "application/json",
    "content-type": "application/json"
}

# will return payload:
#{
#  "access_token": "tokenhere",
#  "token_type": "Bearer",
#  "expires_in": 14400
#}

if (debuglevel > 1):
  print("DEBUG: getting authorization token")

# get authorization token
response = requests.post(exaauthurl, json=payload, headers=headers)
if (debuglevel > 4):
  print("DEBUG: " + response.text)
# load the response JSON data into a dictionary
response_text = json.loads(response.text)

# extract access_token from response dictionary
session_token = response_text['access_token']
token_type = response_text['token_type']
if (debuglevel > 2):
  print("DEBUG: Session token: " + session_token)
  print("DEBUG: Token type: " + token_type)


# =====
# use auth token to perform events query

# =====
# initialize empty set for tracking unique session_ids
unique_session_ids = set()

if (debuglevel > 0):
  print("DEBUG: Loading state from flatfile")

# load previous state from flat file - config file 
if os.path.exists(sessionstatefile):
    with open(sessionstatefile, "r") as f:
        lines = f.readlines()
        for line in lines:
            session_id, timestamp_str = line.strip().split(",")
            timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            if datetime.datetime.now() - timestamp < datetime.timedelta(weeks=1):
                unique_session_ids.add(session_id)


# =====
# prepare for search query
#
# specify fields are to be returned
# currently we need the query to reference fields that exist
# .. caution should be taken with custom fields  c_  .. if they don't exist,
# .. response will likely return a 400
#
# the only "fields" needed are the user, session_id and raw message.
# since session_url may not be parsed we will pass the raw message to each
# destination so any parsing needed is handled by the destination system
#
payload = {
    "fields": ["user", "session_id", "rawLogs"],
    "limit": 3000,
    "distinct": False,
    "startTime": startTime,
    "endTime": endTime,
    "filter": "vendor:\"Exabeam\" AND activity_type:\"alert-trigger\" AND NOT session_id:null"
}

headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": token_type + " " + session_token
}

# perform API query with session token
if (debuglevel > 0):
  print("DEBUG: Performing data query")

# TODO - add try block to catch requests.post failure
response = requests.post(exasearchurl, json=payload, headers=headers)

# check if API request was successful
if response.status_code == 200:
    # parse response JSON data
    data = json.loads(response.content)
    
    # check if any new session_ids are present
    for row in data.get("rows", []):
        session_id = row.get("session_id")
        identifier = session_id.split('-')[0]
        if (debuglevel > 4):
            print("DEBUG: session_id: " + str(session_id) + " identifier: " + str(identifier))
        if session_id not in unique_session_ids and identifier not in blacklist:
            unique_session_ids.add(session_id)
            if (debuglevel > 0):
              print("DEBUG: New session_id found " + session_id)

            # send unique session_id to destination via syslog TLS
            # since session_url may not be reliably parsed, send rawlog for
            # destination to parse out .. otherwise, build string to send first
            rawlog = row.get("rawLogs")
            if (debuglevel > 3):
              print("DEBUG: Sending syslog: new session_id: " + session_id)
            if (debuglevel > 4):
              print("DEBUG: Sending: " + str(rawlog))
            #logger.info(str(row))
            logger.info(rawlog)
            # add sleep for rate limit
            time.sleep(0.3)

            # append new session_id to flat file with timestamp
            with open(sessionstatefile, "a") as f:
                timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"{session_id},{timestamp_str}\n")
                if (debuglevel > 3):
                  print("DEBUG: Wrote state for new session_id: " + session_id)
        elif session_id in unique_session_ids:
          if (debuglevel > 0):
            print("DEBUG: Skipping previously seen session_id " + session_id)
        elif identifier in blacklist:
          if (debuglevel > 0):
            print("DEBUG: Skipping blacklisted identifier in session_id " + session_id)


else:
    # handle API request failure
    print("ERROR: Query API request failed: " + str(response.status_code))
    logger.error("ERROR: Query API request failed: " + str(response.status_code))


# =====
# clean up

# remove session_id entries older than one week from flat file .. keep sent session_id
# for troubleshooting and performance validation
if (debuglevel > 0):
  print("DEBUG: Cleaning up old entries from statefile")
# ensure statefile exists - create empty if not
open(sessionstatefile, 'a').close()
with open(sessionstatefile, "r") as f:
    lines = f.readlines()
with open(sessionstatefile, "w") as f:
    for line in lines:
        session_id, timestamp_str = line.strip().split(",")
        timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() - timestamp < datetime.timedelta(weeks=1):
            f.write(line)

# =====
# release the lock and close the lock file
fcntl.lockf(lock_file, fcntl.LOCK_UN)
lock_file.close()
os.remove(lockfile)
