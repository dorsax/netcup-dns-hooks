#!/usr/bin/python3

import json
import requests
from datetime import datetime
import argparse
import configparser
from copy import deepcopy
import os

#responsible for the arguments
parser = argparse.ArgumentParser(description='Hooks into the netcup DNS API to set the DNS Record for the ACME challenge.')
parser.add_argument('domainname',
                                   help='domain to be modified.')
parser.add_argument('validation',
                                   help='validation string')
parser.add_argument('--cleanup', dest='onlycleanup', action='store_true',
                                   help='yes/no')
parser.add_argument('--debug', dest='debug', action='store_true',
                                   help="Enable debug messages")
args = parser.parse_args()
debug=args.debug
domainname=args.domainname
onlycleanup=args.onlycleanup
validationstring=args.validation

#load the config
config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__))+os.path.sep+'config.ini')

uri = config['global'].get('uri')
apikey= config['credentials'].get('apikey')
apipassword=config['credentials'].get('apipassword')
customernumber= config['credentials'].get('customernumber')

if uri == None: exit("URI not present in config. aborting...")
if apikey == None: exit("API-Key not present in config. aborting...")
if apipassword == None: exit("API-Password not present in config. aborting...")
if customernumber == None: exit("Customernumber not present in config. aborting...")

#how to call the api
def call_api(payload):
    response = requests.post(uri,payload)
    return json.loads(response.text)

#build the pbodies of the payload
standardArray = {}
standardArray["param"]= {}
standardArray["param"]["customernumber"]=customernumber
standardArray["param"]["apikey"]=apikey
standardArray["param"]["clientrequestid"]="acmeChallenge"

def payloadbuilder (pl_type):
    newArray = deepcopy(standardArray)
    newArray["action"]=pl_type  
    return newArray

#Login
loginArray = payloadbuilder("login")
loginArray["param"]["apipassword"]=apipassword
login = json.dumps(loginArray)
loginResponse = call_api(login)

if debug :
    print(json.dumps(loginArray,indent=4))
    print(json.dumps(loginResponse,indent=4))

#quit if something is wrong with the login
if loginResponse["statuscode"] != 2000:
    exit(loginResponse)

#build the remaining payloads
standardArray["param"]["apisessionid"] = loginResponse["responsedata"]["apisessionid"]
logoutArray = payloadbuilder("logout")

standardArray["param"]["domainname"] = domainname
infoDnsRecordsArray = payloadbuilder("infoDnsRecords")
updateDnsRecordsArray = payloadbuilder("updateDnsRecords")

logout = json.dumps(logoutArray)
infoDnsRecords=json.dumps(infoDnsRecordsArray)

#get current dns records
infoDnsRecordsResponse = call_api(infoDnsRecords)
infoDnsRecords=infoDnsRecordsResponse["responsedata"]["dnsrecords"]

if debug:
    print(json.dumps(infoDnsRecordsArray,indent=4))
    print(json.dumps(infoDnsRecordsResponse,indent=4))

#set the acme challenge entry
newRecords = []

#if this is solely a cleanup, do not add the new record
if not onlycleanup:
    newRecords.append({})
    newRecords[0] = {}
    newRecords[0]["hostname"] = "_acme-challenge"
    newRecords[0]["type"]="TXT"
    newRecords[0]["priority"]="0"
    newRecords[0]["deleterecord"]=False
    newRecords[0]["destination"]=validationstring
    newRecords[0]["state"]="yes"

#search for any older acme challenge entries and set them to be removed
for x in range(len(infoDnsRecords)):
    if infoDnsRecords[x]["hostname"] == "_acme-challenge":
        newRecords.append(infoDnsRecords[x])
        newRecords[len(newRecords)-1]["deleterecord"]=True


#update DNS only, if there is something to update
if len(newRecords)!=0:
    #add the dnsrecords to the JSON
    updateDnsRecordsArray["param"]["dnsrecordset"]={}
    updateDnsRecordsArray["param"]["dnsrecordset"]["dnsrecords"] = []
    updateDnsRecordsArray["param"]["dnsrecordset"]["dnsrecords"] = newRecords
    updateDnsRecords = json.dumps(updateDnsRecordsArray)

    #update DNS
    updateDnsRecordsResponse = call_api(updateDnsRecords) 
    
    if debug:
        print(json.dumps(updateDnsRecordsArray,indent=4))
        print(json.dumps(updateDnsRecordsResponse,indent=4))
    
    if updateDnsRecordsResponse["statuscode"]!= 2000:
        print("Error updating DNS records")
        print(updateDnsRecordsResponse["longmessage"])
else:
    print("No update required.")

#logout
logoutResponse = call_api(logout)
if debug:
    print("Script ended.")

