#!/usr/bin/python3
#
# notables-to-jira.py
#
# v1.2
#
# Uses Search API calls to an Exabeam NewScale(tm) tenant
# to find Notable User and Notable Asset notification events.
# Keeps track of notable sessions found and sends any new
# sessions discovered since the last poll to a JIRA webhook
# destination.
#
# Polls an arbitrary number of Exabeam tenants per configuration
# file, however only sends to a single JIRA webhook destination.
# State files are maintained to track unique sessions encountered
# within each tenant and optionally a blocklist of user or assets
# to ignore.
#
# All configuration is done through a configuration file
# "notables-to-jira.json" in JSON format.
#
# Typical use in crontab:
# m h  dom mon dow   command
#0,15,30,45 * * * * cd /home/exabeam/notables; /home/exabeam/notables/notables-to-jira.py >/home/exabeam/notables/notables.log 2>&1
#
#
# Copyright 2023, Allen Pomeroy - MIT license
#
# v1.2
# - initial version

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
# PROOF OF CONCEPT CODE ONLY, NOT SUITABLE FOR PRODUCTION
# ===============================================================


import json
import requests
import time
import os
import datetime
import fcntl
import re
from requests.auth import HTTPBasicAuth



def read_config(filename):
    # Reading the JSON configuration file
    with open(filename, 'r') as f:
        config = json.load(f)
    return config

def get_keys(json_object, parent_key=''):
    keys_list = []
    if isinstance(json_object, dict):
        for key in json_object:
            new_key = f"{parent_key}.{key}" if parent_key else key
            keys_list.append(new_key)
            keys_list.extend(get_keys(json_object[key], new_key))
    return keys_list

def get_value(map_2d, key, value_name):
    # Returns the value associated with the given key and value_name, or None if the key or value_name is not in the map
    return map_2d.get(key, {}).get(value_name)

def get_values_by_search_value(map_2d, search_value):
    # Returns the keys associated with the value that contains the given search_value, or None if the search_value is not in the map
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

def dump_customer_keys(customer):
    # Use the customer_config like a dictionary
    print("DEBUG: dump customer " + customer.get('id') + " keys:")
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
        print('  jiraProjectId:', customer.get('jiraProjectId'))
        print('  jiraUrl:', customer.get('jiraUrl'))
        print('  jiraUser:', customer.get('jiraUser'))
        print('  jiraToken:', customer.get('jiraToken'))
        print('  debuglevel:', customer.get('debuglevel'))
        print('  sessionFile:', customer.get('sessionFile'))
        print('  lockFile:', customer.get('lockFile'))
        print('  logFile:', customer.get('logFile'))
        print('  blocklistFile:', customer.get('blocklistFile'))
        print('  disable:', customer.get('disable'))



if __name__ == "__main__":

    # load configuration file
    config = read_config('notables-to-jira.json')

    # create reverse lookup map
    reverse_lookup = create_reverse_lookup(config)

    # Get a list of all keys in the config file
    keys = get_keys(config)

    # process global flags
    value = get_value(config, "global", "disableAll")
    if value != "False":
        # global disableAll set to True
        print("WARNING: global disableAll is set, exiting")
        exit(1)
    globalDebuglevel = get_value(config, "global", "debuglevel")
    if globalDebuglevel > 0:
        print("DEBUG: global debuglevel set to " + str(globalDebuglevel))
    if globalDebuglevel > 4:
        print("DEBUG: dump all keys:")
        print(keys)
    scriptRoot = get_value(config, "global", "scriptRoot")


    # build a list of all parent (top-level) keys in the config file
    parent_keys = [key for key in config.keys() if not key.startswith('_') and key != 'global']


    # iterate through all customer entries in config file via parent keys
    if globalDebuglevel > 0:
        print("DEBUG: loop through parent customer keys")
    for customerId in parent_keys:
        # Select a specific customer config
        customer_config = config.get(customerId)

        # display customer id
        print("INFO: starting customerId: " + customer_config.get('id'))

        # setup variables for this customer
        debuglevel = int(customer_config.get('debuglevel'))
        if debuglevel > 4:
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
        jiraProjectId = customer_config.get('jiraProjectId')
        jiraUrl = customer_config.get('jiraUrl')
        jiraUser = customer_config.get('jiraUser')
        jiraToken = customer_config.get('jiraToken')
        sessionFile = scriptRoot + "/" + customer_config.get('id') + "_" + customer_config.get('sessionFile')
        lockFile = scriptRoot + "/" + customer_config.get('id') + "_" + customer_config.get('lockFile')
        logFile = scriptRoot + "/" + customer_config.get('id') + "_" + customer_config.get('logFile')
        blocklistFile = scriptRoot + "/" + customer_config.get('id') + "_" + customer_config.get('blocklistFile')
        testFlag = customer_config.get('testFlag')
        disable = customer_config.get('disable')

        if debuglevel > 2:
            print("DEBUG: sessionFile: " + sessionFile)
            print("DEBUG: lockFile: " + lockFile)
            print("DEBUG: logFile: " + logFile)
            print("DEBUG: blocklistFile: " + blocklistFile)

        # abort this customer if disable flag
        if disable == "True":
            print("INFO: skipping customer instance " + customerId + " - disable flag set")
            continue;

        # check for global flags
        value = get_value(config, "global", "disableAll")
        if value != "False":
            print("WARNING: global disableAll is set, exiting")
            exit(1)

        # ensure we are not already running - get lock file
        try:
            lock_file = open(lockFile, "w")
            fcntl.lockf(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if (debuglevel > 0):
              print('DEBUG: ' + customerId + ' lock successfully acquired')
        except IOError as e:
            print("ERROR: " + customerId + " another instance is already running or failed to get lock file.")
            exit(1)


        # =====
        # read blocklist if any - prevents any specified user or asset
        # from being sent to any destination
        # ensure file exists - create blank if not
        open(blocklistFile, 'a').close()
        if debuglevel > 4:
            print("DEBUG: blocklistFile " + blocklistFile)
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
        now = datetime.datetime.now()

        lookbackparts = lookbackTime.split("=")
        timeunit = lookbackparts[0].strip(' "')
        timevalue = int(lookbackparts[1].strip(' "'))

        deltaString = f"datetime.timedelta({timeunit}={timevalue})"
        deltaTime = eval(deltaString)
        pastTime = now - deltaTime

        startTime = pastTime.isoformat() + 'Z'
        endTime = now.isoformat() + 'Z'
        if (debuglevel > 0):
          print("INFO: query startTime: " + str(startTime) + " endTime: " + str(endTime))



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

        if (debuglevel > 1):
          print("DEBUG: getting authorization token")

        # get authorization token
        response = requests.post(authUrl, json=payload, headers=headers)
        if (debuglevel > 4):
          print("DEBUG: " + response.text)
        # load the response JSON data into a dictionary
        response_text = json.loads(response.text)

        # extract access_token from response dictionary
        session_token = response_text['access_token']
        token_type = response_text['token_type']
        if (debuglevel > 2):
          print("DEBUG: session token: " + session_token)
          print("DEBUG: token type: " + token_type)



        # =====
        # initialize empty set for tracking unique session_ids
        unique_session_ids = set()
        
        if (debuglevel > 0):
          print("INFO: loading state from flatfile")
        
        # load previous state from flat file - config file
        if os.path.exists(sessionFile):
            if debuglevel > 4:
                print("DEBUG: sessionFile " + sessionFile)
            with open(sessionFile, "r") as f:
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
            "authorization": token_type + " " + session_token
        }
        
        # perform API query with session token
        if (debuglevel > 0):
          print("INFO: performing data query")
        
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
                if (debuglevel > 4):
                    print("DEBUG: session_id: " + str(session_id) + " identifier: " + str(identifier))
                if session_id not in unique_session_ids and identifier not in blocklist:
                    unique_session_ids.add(session_id)
                    print("INFO: New session_id found " + session_id)
        
                    # send unique session_id to destination via webhook
                    # since session_url may not be reliably parsed, send rawlog for
                    # destination to parse out .. otherwise, build string to send first
                    rawlog = row.get("rawLogs")
                    if (debuglevel > 3):
                      print("DEBUG: Sending new session_id: " + session_id)
                    if (debuglevel > 4):
                      print("DEBUG: rawlog: " + str(rawlog))


                    # 
                    customer_name = get_value(config, customerId, "customerName")
                    if not customer_name:
                        print("WARNING: no customer name found for customerId " + customerId)
                        customer_name = "NotFound"
                    #else:
                    #    print("customer id found: " + looked_up_customer_id)
                    #    # get auth token for url via customer id
                    #    newauthtoken = get_value(config, looked_up_customer_id, "authKey")
                    #    print("new auth token looked up: " + newauthtoken)


                    # extract strings from rawlog

                    # notable line
                    # id="afranklin-20230803160526" url="https://partnerlab2.aa.exabeam.com/uba/#user/#user/afranklin/timeline/afranklin-20230803160526" score="91" start_time="2023-08-03T16:05:26Z" end_time="Ongoing" status="open" user="afranklin" src_host="osx-2212-afran" src_ip="192.168.24.3" accounts="afranklin" labels="" assets="" zones="" top_reasons="Risk transfer from past sessions., This is an occurrence of this DLP alert name for the user, This is an occurrence of USB write alert for the user" reasons_count="3" events_count="1" alerts_count="0" sequence_type="session"
                    
                    # Create a dictionary to store the extracted values
                    rawlog_kvp = {}
                    
                    # Find all matches of the pattern and save them in the dictionary
                    for match in re.findall(r'(\w+)="([^"]*)"', str(rawlog)):
                        rawlog_kvp[match[0]] = match[1]
                    
                    # Print the extracted values
                    if debuglevel > 3:
                        print("DEBUG: rawlog_kvp: " + rawlog_kvp)

                    url = "url: " + rawlog_kvp['url']
                    score = "score: " + rawlog_kvp['score']
                    assets = "assets: " + rawlog_kvp['assets']
                    zones = "zones: " + rawlog_kvp['zones']
                    top_reasons = "top_reasons: " + rawlog_kvp['top_reasons']

                    description = url + "\n" + score + "\n" + assets + "\n" + zones + " \n" + top_reasons

                    # desired webhook payload format:
                    # (TEST) Exabeam - New Notable Session - Client Name - Criticality:(sev/crit)

                    # create summary string for JIRA
                    # TODO - extract risk_score and replace session_id with risk_score
                    summary = "Exabeam - New Notable Session - " + str(customer_name) + " identifier: " + str(identifier) + " risk score: " + str(risk_score)
                    if testFlag == "True":
                        summary = "(TEST) " + summary

                    # setup JIRA field json
                    jiraJsonText = {
                      "fields": {
                        "project": {
                            "key": jiraProjectId
                        },
                        "summary": summary,
                        "description": description,
                        "issuetype": {
                            "name": "Bug"
                        }
                      }
                    }

                    restheaders = {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + jiraToken
                    }

                    if debuglevel > 4:
                        print("DEBUG: jiraJsonText = " + str(jiraJsonText))

                    # Convert your row into JSON format
                    #row_json = json.dumps(row)
                    row_json = json.dumps(jiraJsonText)

                    if debuglevel > 2:
                        print("DEBUG: making webhook call with data: " + row_json)

                    # Make the POST request to send data to destination API
                    restresponse = requests.post(jiraUrl, headers=restheaders, data=row_json, auth=HTTPBasicAuth(jiraUser, jiraToken))

                    # Print the status code and returned data
                    if debuglevel > 4:
                        print(f"Destination Status code: {restresponse.status_code}")
                        print(f"Destination Response: {restresponse.json()}")


                    # add sleep for rate limit
                    time.sleep(0.3)
        
                    # append new session_id to flat file with timestamp
                    with open(sessionFile, "a") as f:
                        timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        f.write(f"{session_id},{timestamp_str}\n")
                        if (debuglevel > 3):
                          print("DEBUG: Wrote state for new session_id: " + session_id)

                elif session_id in unique_session_ids:
                  if (debuglevel > 0):
                    print("INFO: skipping previously seen session_id " + session_id)

                elif identifier in blocklist:
                  if (debuglevel > 0):
                    print("INFO: skipping blocklisted identifier in session_id " + session_id)
        
        
        else:
            # handle API request failure
            print("ERROR: query API request failed: " + str(response.status_code))
            #logger.error("ERROR: Query API request failed: " + str(response.status_code))
        

        # =====
        # clean up
        
        # remove session_id entries older than one week from flat file .. keep sent session_id
        # for troubleshooting and performance validation
        if (debuglevel > 0):
          print("INFO: cleaning up old entries from statefile")

        # ensure statefile exists - create empty if not
        open(sessionFile, 'a').close()
        with open(sessionFile, "r") as f:
            lines = f.readlines()
        with open(sessionFile, "w") as f:
            for line in lines:
                session_id, timestamp_str = line.strip().split(",")
                timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                if datetime.datetime.now() - timestamp < datetime.timedelta(days=1):
                    f.write(line)
        
        # =====
        # release the lock and close the lock file
        fcntl.lockf(lock_file, fcntl.LOCK_UN)
        lock_file.close()
        os.remove(lockFile)

    # iterate to next customer
