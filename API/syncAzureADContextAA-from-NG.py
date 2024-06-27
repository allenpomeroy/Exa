#!/usr/bin/python3
#
# syncAzureADContextAA-from-NG.py
#
# v1.1 2024/05/01 AP
# - add debug statements to display progress
# - amalgamated from several sources
#
# usage:
# ./syncAzureADContextAA-from-NG.py -a NS-AzureAD-ContextTableName -d true
#
# ----------------------------------------------------------------------------------------------------- #
# Sync Azure AD Context to AA from NG Context Tables                                                    #
# This is designed to sync Azure AD context to AA so that you can support multiple Azure AD deployments #
# Disclaimer: This script is provided as is with no warranties                                          #
# ----------------------------------------------------------------------------------------------------- #

# The script performs the following:
#   1. Connects to NG and pulls NG Context Tables to lookup the ID.
#   2. Connects to NG and pulls all records for the Table by ID.
#   3. Creates several lists (CSV) data to be imported in AA.
#   4. For each list (CSV) the data is populated in the applicable AA table and made live

import requests
import json
import argparse
import sys


# Base URL and Credentials for Exabeam Security Operations Platform (BE SURE TO UPDATE FOR YOUR DEPLOYMENT)
base_url = "https://api.us-east.exabeam.cloud"
aa_base_url = "https://partnerlab2.aa.exabeam.com"
client_id = "C8QzZZgWwxxxxxxxxxxxxxxxxxxxxxvsVcxZ"
client_secret = "DP4psV8dGFTaxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxOkf"
aa_cluster_auth_token = "803axxxb-7xxx-4xxx-aexx-dxxxxxxxxxxb"
row_limit = "5000"
record_offset = "0"

# Context Tables Updated
# user_fullname
# email_user
# fullname_user
# azure_id_user_type
# user_azure_on_premises_sam_account_name
# user_azure_mail_nickname
# user_azure_display_name
# user_azure_mail
# user_azure_user_principal_name
# user_azure_object_id

# user_department
# location
# user_title
# user_phone_cell

# Default API Endpoint Paths
login_url = "/auth/v1/token"
context_url = "/context-management/v1/tables"
aa_context_url = "/eds/api/contextTables"

# Input Fields (NG Context Table | NG Table Field | AA Context Table | Overwite yes/no)
argParser = argparse.ArgumentParser()
argParser.add_argument("-a", "--azureADTable", required=True, help="Which table should you read from in NG Context Management.")
argParser.add_argument("-c", "--concatName", required=False, default="", help="Concatenate text to the users Full Name. This will appear in brackets at the end. Sometimes helpful as an identifier (Could break some full name enrichers).")
argParser.add_argument("-ot", "--optionalContext", required=False, action='store_true', default=True, help="Adds to additional context to other tables on location, title and cell number.")
argParser.add_argument("-ov", "--overwrite", required=False, default=False, type=bool, help="Choose whether to overwrite the entire table with result set. You can do this is if you dont have manual entries or pushing multiple Azure AD context using this script. THIS DOES NOT OVERWRITE THE CONTEXT PULLED NATIVELY BY AA (ALL AD / AZURE AD WILL NOT BE OVERWRITTEN) (Default: False)")
argParser.add_argument("-d", "--debug", required=False, default=False, type=bool, help="Display progress and debug information. (Default: False)")
args = argParser.parse_args()

# Build the schemas for the CSVs for uploading into AA
concatName = ""
if (args.concatName != ""):
    concatName = " (" + args.concatName + ")"

user_account = "account_id,account_id\n"
user_fullname = "account_id,title\n"
email_user = "account_id,title\n"
fullname_user = "account_id,title\n"
user_email = "account_id,title\n"
azure_id_user_type = "account_id,title\n"
user_azure_on_premises_sam_account_name = "account_id,title\n"
user_azure_mail_nickname = "account_id,title\n"
user_azure_display_name = "account_id,title\n"
user_azure_mail = "account_id,title\n"
user_azure_user_principal_name = "account_id,title\n"
user_azure_object_id = "account_id,title\n"
user_department = "account_id,title\n"
user_location = "account_id,title\n"
user_title = "account_id,title\n"
user_phone_cell = "account_id,title\n"

# Authenticate to the NG API and grab the authentication token
payload = {
    "grant_type": "client_credentials",
    "client_id": client_id,
    "client_secret": client_secret
}
headers = {
    "accept": "application/json",
    "content-type": "application/json"
}

try:
    response = requests.post(base_url + login_url, json=payload, headers=headers)
    if (args.debug):
        print("authenticate response: " + str(response.text) + "\n")
    if ("error_description" in response.text): raise Exception(response.text)
except requests.exceptions.HTTPError as e:
    raise SystemExit(e)
except requests.exceptions.RequestException as e:
    raise SystemExit(e)

j = json.loads(response.text)
token = j["access_token"]

headers = {
    "accept": "application/json",
    "authorization": "Bearer " + token
}

# Create a connection to NG and grab the relevant Context Table ID
try:
    response = requests.get(base_url + context_url, headers=headers)
    if (args.debug):
        print("context id response: " + str(response.text) + "\n")
    if ("error_description" in response.text): raise Exception(response.text)
except requests.exceptions.HTTPError as e:
    raise SystemExit(e)
except requests.exceptions.RequestException as e:
    raise SystemExit(e)

j = json.loads(response.text)
id = 0

for t in j:
    if (args.debug):
        print("j: {}".format(j))
        print("")
    if (t["name"] == args.azureADTable):
        id = t["id"]

if (id == 0): raise Exception("Error: Input Table Not Found.")

headers = {
    "accept": "application/json",
    "authorization": "Bearer " + token
}

# Create a connection to NG and pull Context Table by ID
try:
    response = requests.get(base_url + context_url + "/" + id + "/records?limit=" + row_limit + "&offset=" + record_offset, headers=headers)
    if (args.debug):
        print("context response: " + str(response.text) + "\n")
    if ("error_description" in response.text): raise Exception(response.text)
except requests.exceptions.HTTPError as e:
    raise SystemExit(e)
except requests.exceptions.RequestException as e:
    raise SystemExit(e)

j = json.loads(response.text)

# Populate the CSVs
if (args.debug):
    print("populate CSVs for upload\n")

aa_count = 0
for r in j["records"]:
    # AP: change to use First Name and Last Name for NS-AzureAD-Context
    # get first and last name, concat and insert into fullname
    # versus using azure ad fullname (allows rolling admin account and normal
    # together)

    # u_user should map to samAccountName (user_account in AA)
    # {"sourceAttribute":"sAMAccountName","targetAttributeId":"u_user"}

    #
    if r.get('u_user') is not None and "gmail" not in r.get('u_user'):
        # u_user is not null so process context entry
        # .. also any u_user that contains gmail will be skipped

        # --------------------
        # account processing

        user_account += r["u_user"].lower() + "," + r["u_user"].lower() + "\n"

        # --------------------
        # full name processing

        # build fullname = fname + " " + lname
        if r.get('u_fname') is not None and r.get('u_lname') is not None:
            fullname = r["u_fname"] + " " + r["u_lname"]
            fullname_user += fullname + concatName + "," + r["u_user"].lower() + "\n"
            user_fullname += r["u_user"].lower() + "," + fullname + concatName + "\n"

            # {"displayName":"Primary Login (Email Format)","id":"u_account"
            # {"displayName":"Primary User Name","id":"u_user"
            #
            # Primary Login (Email Format) > Primary User Name
            # u_account                    > u_user
            # john.smith@example.com       > john.smith


        # --------------------
        # email processing

        if r.get('u_account') is not None:
            email_user += r["u_account"].lower() + "," + r["u_user"].lower() + "\n"
            user_email += r["u_user"].lower() + "," + r["u_account"].lower() + "\n"


        # --------------------
        # dept processing

        if r.get('u_department') is not None:
            user_department += r["u_user"] + "," + r["u_department"] + "\n"

        # --------------------
        # location processing

        if r.get('u_city') is not None:
            user_location += r["u_user"] + "," + r["u_city"] + "\n"

        # --------------------
        # title processing

        if r.get('u_title') is not None:
            user_title += r["u_user"] + "," + r["u_title"] + "\n"

        # --------------------
        # mobile processing

        if r.get('u_mobile') is not None:
            user_phone_cell += r["u_user"] + "," + r["u_mobile"] + "\n"


    # azure_id_user_type
    if not (r.get('u_account') is None):
        if ("#EXT#" in r["u_account"]):
            azure_id_user_type += r["u_user"] + ",Guest\n"
        else:
            azure_id_user_type += r["u_user"] + ",Member\n"

    # user_azure_on_premises_sam_account_name
    if not (r.get('u_user') is None):
        user_azure_on_premises_sam_account_name += r["u_user"] + "\n"

    # user_azure_mail_nickname
    if not (r.get('u_user') is None) and not (r.get('u_user') is None):
        user_azure_mail_nickname += r["u_user"] + "," + r["u_user"] + "\n"

    # user_azure_display_name
    if not (r.get('u_user') is None) and not (r.get('u_dname') is None):
        user_azure_display_name += r["u_user"] + "," + r["u_dname"] + "\n"

    # user_azure_mail
    if not (r.get('u_user') is None) and not (r.get('u_account') is None):
        user_azure_mail += r["u_user"] + "," + r["u_account"] + "\n"

    # user_azure_user_principal_name
    if not (r.get('u_user') is None) and not (r.get('u_account') is None):
        user_azure_user_principal_name += r["u_user"] + "," + r["u_account"] + "\n"

    # user_azure_object_id
    if not (r.get('u_user') is None) and not (r.get('id') is None):
        user_azure_object_id += r["u_user"] + "," + r["id"] + "\n"

    aa_count += 1

# Remove the trailing space
user_account = user_account[:-1]
user_fullname = user_fullname[:-1]
email_user = email_user[:-1]
fullname_user = fullname_user[:-1]
user_email = user_email[:-1]
user_department = user_department[:-1]
user_location = user_location[:-1]
user_title = user_title[:-1]
user_phone_cell = user_phone_cell[:-1]

azure_id_user_type = azure_id_user_type[:-1]
user_azure_on_premises_sam_account_name = user_azure_on_premises_sam_account_name[:-1]
user_azure_mail_nickname = user_azure_mail_nickname[:-1]
user_azure_display_name = user_azure_display_name[:-1]
user_azure_mail = user_azure_mail[:-1]
user_azure_user_principal_name = user_azure_user_principal_name[:-1]
user_azure_object_id = user_azure_object_id[:-1]

# Function to simplify uploading each data set to AA
def uploadAAData(aa_data, table_name):
    
    # Do nothing if the table is empty
    if (aa_data.count("\n") <= 1):
        print(table_name + ": Empty")
        return

    headers = {
        "Csrf-Token": "nocheck",
        "ExaAuthToken": aa_cluster_auth_token
    }

    aa_file = {'data': ('readme.txt', aa_data, 'text/plain')}

    aa_session_id = ""

    # Bulk upload the CSV records
    try:
        response = requests.post(aa_base_url + aa_context_url + "/" + table_name + "/changes/addBulk?hasHeader=true", headers=headers, files=aa_file)
        if not ("sessionId" in response.text): raise Exception(response.text)
    except requests.exceptions.HTTPError as e:
        raise SystemExit(e)
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)

    j = json.loads(response.text)
    if not (j.get("sessionId") is None):
        aa_session_id = j["sessionId"]

    if (aa_session_id == ""): raise Exception("Error: Could not extract AA Session ID.")


    headers = {
        "Csrf-Token": "nocheck",
        "ExaAuthToken": aa_cluster_auth_token,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    # Update EDS to make the bulk upload live in EDS
    try:
        if (args.overwrite == True):
            response = requests.put(aa_base_url + aa_context_url + "/" + table_name + "/records", data='{ "sessionId": "' + aa_session_id + '", "replace": true }', headers=headers)
        else:
            response = requests.put(aa_base_url + aa_context_url + "/" + table_name + "/records", data='{ "sessionId": "' + aa_session_id + '", "replace": false }', headers=headers)
    except requests.exceptions.HTTPError as e:
        raise SystemExit(e)
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)

    print("Uploaded: " + table_name)


# Call the function and upload each CSV
uploadAAData(user_account,    "user_account")

uploadAAData(user_fullname,   "user_fullname")
uploadAAData(fullname_user,   "fullname_user")
# no user_email table in AA
#uploadAAData(user_email,      "user_email")
uploadAAData(email_user,      "email_user")

uploadAAData(user_title,      "user_title")
uploadAAData(user_department, "user_department")
uploadAAData(user_location,   "user_location")
uploadAAData(user_phone_cell, "user_phone_cell")

uploadAAData(azure_id_user_type, "azure_id_user_type")
uploadAAData(user_azure_on_premises_sam_account_name, "user_azure_on_premises_sam_account_name")
uploadAAData(user_azure_mail_nickname, "user_azure_mail_nickname")
uploadAAData(user_azure_display_name, "user_azure_display_name")
uploadAAData(user_azure_mail, "user_azure_mail")
uploadAAData(user_azure_user_principal_name, "user_azure_user_principal_name")
uploadAAData(user_azure_object_id, "user_azure_object_id")

# example test context tables could be used first to test script
#uploadAAData(user_fullname, "ap_user_fullname")
#uploadAAData(fullname_user, "ap_fullname_user")
#uploadAAData(email_user,    "ap_email_user")
