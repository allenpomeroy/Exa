#!/usr/bin/python3
#
# notables-to-syslog.py
#
# v1.12
# - cleaned up debug / informational message levels
# v1.11
# - update to use cached auth token until expiry
#
# Uses Search API calls to an Exabeam NewScale(tm) tenant
# to find Notable User and Notable Asset notification events.
# Keeps track of notable sessions found and sends any new
# sessions discovered since the last poll to all configured
# syslog TLS destinations.
#
#*****************************************
# Polls an arbitrary number of Exabeam tenants per configuration
# file, however only sends to a single JIRA webhook destination.
# State files are maintained to track unique sessions encountered
# within each tenant and optionally a blocklist of user or assets
# to ignore.
#
# All configuration is done through a configuration file
# "notables-to-syslog.json" in JSON format.
#
# Typical use in crontab:
# m h  dom mon dow   command
#0,15,30,45 * * * * cd /home/exabeam/notables; /home/exabeam/notables/notables-to-syslog.py >/home/exabeam/notables/0-cron.log 2>&1
#
#
# Copyright 2023, Allen Pomeroy - MIT license
#

# MIT License
# Copyright (c) 2022-2023 allenpomeroy and contributors
# github.com/allenpomeroy/Exa/API/notables-to-syslog.py
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

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
# PROOF OF CONCEPT CODE ONLY, NOT SUITABLE FOR PRODUCTION
# ===============================================================


import syslog
import socket
import logging
import logging.handlers
import ssl
import json
import requests
import time
import os
import fcntl
import re
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta
from dateutil import parser

config_file_path = 'notables-to-syslog.json'
debuglevel = 0

def print_message(mindebuglevel, messagelevel, severity, message):
    if mindebuglevel >= messagelevel:
        #now = datetime.datetime.now()
        now = datetime.now()
        msgTimestamp = now.isoformat()
        
        if severity == 'DEBUG':
            formatted_msg = f"{msgTimestamp}   {severity}{messagelevel}: {message}"
        else:
            formatted_msg = f"{msgTimestamp} {severity}: {message}"

        print(formatted_msg)
        with open(logFile, 'a') as logfile:
            logfile.write(formatted_msg + '\n')

def read_config(filename):
    # load the JSON configuration file
    with open(filename, 'r') as f:
        config = json.load(f)
    return config

class SSLSysLogHandler(logging.Handler):
    """
    A logging handler that sends logs over TCP, wrapped with SSL/TLS.
    """
    def __init__(self, host, port, ssl_context):
        super().__init__()
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.sock = self._create_ssl_socket()

    def _create_ssl_socket(self):
        # Create a socket using TCP (SOCK_STREAM)
        sock = socket.create_connection((self.host, self.port))
        # Wrap the socket with the provided SSL context
        ssl_sock = self.ssl_context.wrap_socket(sock, server_hostname=self.host)
        return ssl_sock

    def emit(self, record):
        try:
            msg = self.format(record) + '\n'  # Syslog typically expects newline-terminated messages
            self.sock.sendall(msg.encode('utf-8'))
        except Exception as e:
            print(f"ERROR: Error encountered with syslog destination {self.host}:{self.port}: {e}")
            self.handleError(record)

    def close(self):
        if self.sock:
            self.sock.close()
        super().close()

#
# auth token management
def get_token_cache_file(customer_key):
    customerId = customer_key.get('id')
    authUrl = customer_key.get('authUrl')
    authKey = customer_key.get('authKey')
    authSecret = customer_key.get('authSecret')
    tokenCacheFile = scriptRoot + "/" + customer_key.get('id') + "_" + customer_key.get('tokenCacheFile')
    #return f'token_cache_{customer_id}.json'
    return tokenCacheFile

def read_token_cache(customer_key):
    try:
        with open(get_token_cache_file(customer_key),'r') as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        return None

def write_token_cache(customer_key, token_data):
    with open(get_token_cache_file(customer_key), 'w') as file:
        json.dump(token_data, file)
        
def is_token_expired(token_data):
    #saved_time = datetime.fromisoformat(token_data['saved_at'])
    saved_time = parser.parse(token_data['saved_at'])
    expires_delta = timedelta(seconds=token_data['expires_in'])
    return datetime.now() >= saved_time + expires_delta

def fetch_new_token(customer_key):
    customerId = customer_key.get('id')
    authUrl = customer_key.get('authUrl')
    authKey = customer_key.get('authKey')
    authSecret = customer_key.get('authSecret')
        
    # =====
    # use api key and secret to generate token

    # contact Exabeam tenant administrator or local Exabeam contact to obtain
    # correct authorization and query URLs.  these are specific to the region
    # a customer tenant is located within

    # authUrl, authKey and authsScret are read from config file
    payload = {
        "grant_type": "client_credentials",
        "client_id": authKey,
        "client_secret": authSecret
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

    print_message(debuglevel, 3, "DEBUG", "fetch_new_token getting authorization token")

    # get authorization token
    response = requests.post(authUrl, json=payload, headers=headers)
    print_message(debuglevel, 5, "DEBUG", response.text)

    # load the response JSON data into a dictionary
    response_text = json.loads(response.text)

    # extract access_token from response dictionary
    access_token = response_text['access_token']
    token_type = response_text['token_type']
    expires_in = response_text['expires_in']

    new_token_data = {
        "access_token": access_token,
        "token_type": token_type,
        "expires_in": expires_in,
        #"saved_at": datetime.datetime.now().isoformat()
        "saved_at": datetime.now().isoformat()
    }

    print_message(debuglevel, 3, "DEBUG", "fetch_new_token new_token_data:")
    print_message(debuglevel, 3, "DEBUG", str(new_token_data))
    write_token_cache(customer_key,new_token_data)
    return new_token_data

# customer instance management
def get_keys(json_object, parent_key=''):
    keys_list = []
    if isinstance(json_object, dict):
        for key in json_object:
            new_key = f"{parent_key}.{key}" if parent_key else key
            keys_list.append(new_key)
            keys_list.extend(get_keys(json_object[key], new_key))
    return keys_list

def get_value(map_2d, key, value_name):
    # returns the value associated with the given key and value_name,
    # or None if the key or value_name is not in the map
    return map_2d.get(key, {}).get(value_name)

def get_values_by_search_value(map_2d, search_value):
    # returns the keys associated with the value that contains the
    # given search_value, or None if the search_value is not in the map
    for key, values in map_2d.items():
        if isinstance(values, dict):
            for inner_key, value in values.items():
                if search_value == value:
                    return key
    return None

def create_reverse_lookup(map_2d):
    reverse_lookup = {}
    for key, value_dict in map_2d.items():
        for value_name, value in value_dict.items():
            reverse_lookup[value] = (key, value_name)
    return reverse_lookup

# define function to setup syslog destinations
def configure_syslog_destinations(customer_config, logger, ssl_context, msgdebuglevel):
    syslogDestCount = int(customer_config.get('syslogDestCount', 0))
    formatter = logging.Formatter('%(asctime)s %(name)s: %(levelname)s %(message)s', datefmt='%b %d %H:%M:%S')

    for i in range(1, syslogDestCount + 1):
        syslogFQDNKey = f'syslog{i}FQDN'
        syslogPortKey = f'syslog{i}Port'
        host = customer_config.get(syslogFQDNKey)
        port = int(customer_config.get(syslogPortKey))

        if host and port:
            try:
                syslog_handler = SSLSysLogHandler(host, port, ssl_context)
                syslog_handler.setFormatter(formatter)
                logger.addHandler(syslog_handler)
                print_message(debuglevel, msgdebuglevel, "INFO", "Syslog destination " + host + ":" + str(port) + " configured for " + customer_config.get('customerName'))
            except Exception as e:
                print(f"ERROR: Error encountered during setup of syslog destination {host}:{port} for {customer_config.get('customerName')}: {e}")


def dump_customer_keys(customer):
    # Use the customer_config like a dictionary
    print_message(debuglevel, 5, "DEBUG", "dump customer " + customer.get('id') + " keys:")
    if customer:
        print('  id:', customer.get('id'))
        print('  customerName:', customer.get('customerName'))
        print('  region:', customer.get('region'))
        print('  authUrl:', customer.get('authUrl'))
        print('  authKey:', customer.get('authKey'))
        print('  authSecret:', customer.get('authSecret'))
        print('  searchUrl:', customer.get('searchUrl'))
        print('  lookbackTime:', customer.get('lookbackTime'))
        print('  customerEcpUrl:', customer.get('customerEcpUrl'))
        print('  customerAAUrl:', customer.get('customerAAUrl'))
        print('  debuglevel:', customer.get('debuglevel'))
        print('  sessionFile:', customer.get('sessionFile'))
        print('  logFile:', customer.get('logFile'))
        print('  blocklistFile:', customer.get('blocklistFile'))
        print('  disable:', customer.get('disable'))



if __name__ == "__main__":
    # load configuration file
    config = read_config(config_file_path)

    # create reverse lookup map
    reverse_lookup = create_reverse_lookup(config)

    # Get a list of all keys in the config file
    keys = get_keys(config)

    # process global flags
    scriptRoot = get_value(config, "global", "scriptRoot")
    logFile = scriptRoot + "/" + get_value(config, "global", "logFile")
    lockFile = scriptRoot + "/" + get_value(config, "global", "lockFile")
    disableAll = get_value(config, "global", "disableAll")
    globalDebuglevel = get_value(config, "global", "debuglevel")
    debuglevel = globalDebuglevel

    print_message(debuglevel, 0, "INFO", f"{__file__} starting up")
    print_message(debuglevel, 2, "INFO", "global debuglevel set to " + str(globalDebuglevel))

    if disableAll != "False":
        # global disableAll set to True
        print_message(debuglevel, 0, "FATAL", "global disableAll is set, exiting")
        exit(1)
    
    # ensure we are not already running - get lock file
    try:
        lock_file = open(lockFile, "w")
        fcntl.lockf(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print_message(debuglevel, 3, "INFO", "lock successfully acquired")
    except IOError as e:
        print_message(debuglevel, 0, "FATAL", "another instance is already running or failed to get lock file " + lockFile)
        exit(1)        


    # setup syslog logger

    # setup common SSL context for all syslog destinations
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    logger = logging.getLogger(__file__)
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s %(name)s: %(levelname)s %(message)s ', datefmt='%b %d %H:%M:%S\n')
    

    # build a list of all parent (top-level) keys in the config file
    parent_keys = [key for key in config.keys() if not key.startswith('_') and key != 'global']


    # iterate through all customer entries in config file via parent keys
    print_message(debuglevel, 4, "DEBUG", "loop through parent customer keys")
    for customerId in parent_keys:
        # reset debuglevel
        debuglevel = globalDebuglevel
        
        # select a specific customer config
        customer_config = config.get(customerId)

        # display customer id
        print_message(debuglevel, 1, "INFO", "Starting customerId: " + customer_config.get('id'))
        
        # setup variables for this customer
        customerDebuglevel = int(customer_config.get('debuglevel'))
        if customerDebuglevel > 0 and customerDebuglevel > globalDebuglevel:
            debuglevel = customerDebuglevel
        if debuglevel > 9:
            dump_customer_keys(customer_config)

        customerId = customer_config.get('id')
        region = customer_config.get('region')
        authUrl = customer_config.get('authUrl')
        authKey = customer_config.get('authKey')
        authSecret = customer_config.get('authSecret')
        searchUrl = customer_config.get('searchUrl')
        lookbackTime = customer_config.get('lookbackTime')
        customerEcpUrl = customer_config.get('customerEcpUrl')
        customerAAUrl = customer_config.get('customerAAUrl')
        sessionFile = scriptRoot + "/" + customer_config.get('id') + "_" + customer_config.get('sessionFile')
        blocklistFile = scriptRoot + "/" + customer_config.get('id') + "_" + customer_config.get('blocklistFile')
        tokenCacheFile = scriptRoot + "/" + customer_config.get('id') + "_" + customer_config.get('tokenCacheFile')
        testFlag = customer_config.get('testFlag')
        disable = customer_config.get('disable')

        # debugging
        print_message(debuglevel, 5, "DEBUG", "sessionFile: " + sessionFile)
        print_message(debuglevel, 5, "DEBUG", "lockFile: " + lockFile)
        print_message(debuglevel, 5, "DEBUG", "logFile: " + logFile)
        print_message(debuglevel, 5, "DEBUG", "blocklistFile: " + blocklistFile)

        # abort this customer if disable flag
        if disable == "True":
            print_message(debuglevel, 0, "WARN", "skipping customer instance " + customerId + " - disable flag set")
            continue;

        # check for global flags
        value = get_value(config, "global", "disableAll")
        if value != "False":
            print_message(debuglevel, 0, "FATAL", "global disableAll is set, exiting")
            exit(1)

        # configure syslog destinations for this customer
        print_message(debuglevel, 3, "INFO", "starting syslog destination configuration")
        configure_syslog_destinations(customer_config, logger, ssl_context, debuglevel)

        #
        # token auth logic
        token_data = read_token_cache(customer_config)
        
        if not token_data or is_token_expired(token_data):
            token_data = fetch_new_token(customer_config)
            print_message(debuglevel, 4, "INFO", "token refreshed for customer")
        else:
            print_message(debuglevel, 4, "INFO", "using cached token for customer")

        access_token = token_data["access_token"]
        token_type = token_data["token_type"]
        
        
        # =====
        # read blocklist if any - prevents any specified user or asset
        # from being sent to any destination
        # ensure file exists - create blank if not
        open(blocklistFile, 'a').close()
        print_message(debuglevel, 5, "DEBUG", "loading blocklistFile " + blocklistFile)
        # load the blocklist from the file
        blocklist = set()
        try:
            with open(blocklistFile, 'r') as f:
                for line in f:
                    userorasset = line.strip()
                    if userorasset:
                        blocklist.add(userorasset)
        except FileNotFoundError:
            pass


        # ===
        # setup date range for this customer tenant

        # setup datetime strings - query back last x time specified by lookbacktime
        now = datetime.now()

        lookbackparts = lookbackTime.split("=")
        timeunit = lookbackparts[0].strip(' "')
        timevalue = int(lookbackparts[1].strip(' "'))

        deltaTime = timedelta(**{timeunit: timevalue})
        pastTime = now - deltaTime

        startTime = pastTime.isoformat() + 'Z'
        endTime = now.isoformat() + 'Z'
        print_message(debuglevel, 3, "INFO", "query startTime: " + str(startTime) + " endTime: " + str(endTime))


        # =====
        # initialize empty set for tracking unique session_ids
        unique_session_ids = set()
        
        print_message(debuglevel, 5, "DEBUG", "loading state from flatfile")
        
        # load previous state from flat file - config file
        if os.path.exists(sessionFile):
            print_message(debuglevel, 6, "DEBUG", "sessionFile " + sessionFile)
            with open(sessionFile, "r") as f:
                lines = f.readlines()
                for line in lines:
                    session_id, timestamp_str = line.strip().split(",")
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    if datetime.now() - timestamp < timedelta(weeks=1):
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
            "fields": ["user", "session_id", "original_risk_score", "rawLogs"],
            "limit": 3000,
            "distinct": False,
            "startTime": startTime,
            "endTime": endTime,
            "filter": "vendor:\"Exabeam\" AND activity_type:\"alert-trigger\" AND NOT session_id:null AND \"top_reasons\""
        }
        
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "authorization": token_type + " " + access_token
        }
        
        # perform API query with session token
        print_message(debuglevel, 3, "INFO", "performing data query")
        
        # TODO - add try block to catch requests.post failure
        response = requests.post(searchUrl, json=payload, headers=headers)
        
        # check if API request was successful
        if response.status_code == 200:
            # parse response JSON data
            data = json.loads(response.content)
            
            # check if any new session_ids are present
            for row in data.get("rows", []):
                session_id = row.get("session_id")
                risk_score = row.get("original_risk_score")
                identifier = session_id.split('-')[0]
                print_message(debuglevel, 4, "DEBUG",  "Found session_id: " + str(session_id) + " identifier: " + str(identifier))
                if session_id not in unique_session_ids and identifier not in blocklist:
                    unique_session_ids.add(session_id)
                    print_message(debuglevel, 1, "INFO", ">>> New session_id found " + session_id)
        
                    # send unique session_id to destination via webhook
                    # since session_url may not be reliably parsed, send rawlog for
                    # destination to parse out .. otherwise, build string to send first
                    rawlog = row.get("rawLogs")
                    print_message(debuglevel, 5, "DEBUG", "Sending new session_id: " + session_id)
                    print_message(debuglevel, 6, "DEBUG", "rawlog: " + str(rawlog))


                    # 
                    customer_name = get_value(config, customerId, "customerName")
                    if not customer_name:
                        print_message(debuglevel, 0, "WARN", "no customer name found for customerId " + customerId)
                        customer_name = "NotFound"

                    # notable line
                    # id="afranklin-20230803160526" url="https://partnerlab2.aa.exabeam.com/uba/#user/#user/afranklin/timeline/afranklin-20230803160526" score="91" start_time="2023-08-03T16:05:26Z" end_time="Ongoing" status="open" user="afranklin" src_host="osx-2212-afran" src_ip="192.168.24.3" accounts="afranklin" labels="" assets="" zones="" top_reasons="Risk transfer from past sessions., This is an occurrence of this DLP alert name for the user, This is an occurrence of USB write alert for the user" reasons_count="3" events_count="1" alerts_count="0" sequence_type="session"

                    # could extract strings from rawlog in order to pre-parse for
                    # a destination system

                    print_message(debuglevel, 6, "DEBUG", "making syslog call with data: " + str(rawlog))

                    # send test message to all syslog dest
                    logger.info(rawlog)


                    # add sleep for rate limit
                    time.sleep(0.3)
        
                    # append new session_id to flat file with timestamp
                    with open(sessionFile, "a") as f:
                        #timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        f.write(f"{session_id},{timestamp_str}\n")
                        print_message(debuglevel, 5, "DEBUG", "Wrote state for new session_id: " + session_id)

                elif session_id in unique_session_ids:
                    print_message(debuglevel, 1, "INFO", ">>> Skipping previously seen session_id " + session_id)

                elif identifier in blocklist:
                    print_message(debuglevel, 1, "INFO", ">>> Skipping blocklisted identifier in session_id " + session_id)
        
        
        else:
            # handle API request failure
            print_message(debuglevel, 0, "ERROR", "query API request failed: " + str(response.status_code))
        

        # =====
        # clean up
        
        # remove session_id entries older than one week from flat file .. keep sent session_id
        # for troubleshooting and performance validation
        print_message(debuglevel, 3, "INFO", "cleaning up old entries from statefile")

        # ensure statefile exists - create empty if not
        open(sessionFile, 'a').close()
        with open(sessionFile, "r") as f:
            lines = f.readlines()
        with open(sessionFile, "w") as f:
            for line in lines:
                session_id, timestamp_str = line.strip().split(",")
                #timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                #if datetime.datetime.now() - timestamp < datetime.timedelta(days=1):
                if datetime.now() - timestamp < timedelta(days=1):
                    f.write(line)
                    
    # iterate to next customer
    
    # =====
    # release the lock and close the lock file
    fcntl.lockf(lock_file, fcntl.LOCK_UN)
    lock_file.close()
    os.remove(lockFile)
