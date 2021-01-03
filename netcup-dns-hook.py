#!/usr/bin/python3.8

version = "0.2"

import sys
import json
import requests
from datetime import datetime
import argparse
import configparser
from copy import deepcopy
import os

#responsible for the arguments
parser = argparse.ArgumentParser(description='Hooks into the netcup DNS API to set any DNS Record.')
fqdn_host= parser.add_mutually_exclusive_group(required = True)
parser.add_argument ('mode',
                    choices = ['add','update','remove'],
                    help = "Choose between adding, removing or updating an entry.")
parser.add_argument('-o','--host',
                    dest = 'host',
                    metavar = 'host',
                    default = '@',
                    help = 'host portion of the entry. Defaults to \'@\' for usage in root scenarios.')
fqdn_host.add_argument('-d','--domainname','--domain',
                    dest = 'domain',
                    metavar = 'domain.com',
                    help = 'domain to be modified')
fqdn_host.add_argument('-f', '--fqdn',
                    dest = "fqdn",
                    metavar = 'host.domain.com',
                    help = 'fully qualified domain name, as a replacement option for domain name and host')

parser.add_argument('-t','--type',
                    dest = 'entrytype',
                    choices = ['TXT', 'A', 'AAAA'], 
                    required = True,
                    help = 'Required. type of the entry.')
       
parser.add_argument('-c', '--current',
                    dest='previous',
                    metavar='127.0.0.1',
                    help='current destination of the entry which needs to be updated/deleted. If missing all entries will be updated or deleted.')

parser.add_argument('-s', '--destination',
                    dest = 'destination',
                    metavar = '127.0.0.1',
                    help = 'destination of the entry, needed if not removing entries')
parser.add_argument('--debug',
                    dest = 'debug', 
                    action = 'store_true',
                    help = "Enable debug messages")
parser.add_argument('--version', 
                    action = 'version', 
                    version = 'You are running version: '+version)

args = parser.parse_args()
mode = args.mode
debug = args.debug
domain = args.domain
host = args.host
fqdn = args.fqdn
current_destination = args.current
new_destination = args.destination
entrytype = args.entrytype

if (mode != "remove") and (not destination):
    parser.error("No destination provided.")

#split the fqdn to host and domain portion
if fqdn: 
    index = fqdn.rfind(".",0,fqdn.rfind("."))
    if index == -1:
        domain = fqdn
        host = "@"
    else:
        domain = fqdn[index+1:]
        host = fqdn[:index]
        



#load the config
config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__))+os.path.sep+'config.ini')

uri = config['global'].get('uri')
apikey = config['credentials'].get('apikey')
apipassword = config['credentials'].get('apipassword')
customernumber = config['credentials'].get('customernumber')

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
standardArray["param"] = {}
standardArray["param"]["customernumber"] = customernumber
standardArray["param"]["apikey"] = apikey
standardArray["param"]["clientrequestid"] = "dns-hook"

def payloadbuilder (pl_type):
    newArray = deepcopy(standardArray)
    newArray["action"] = pl_type  
    return newArray

#Login
loginArray = payloadbuilder("login")
loginArray["param"]["apipassword"] = apipassword
login = json.dumps(loginArray)
loginResponse = call_api(login)

if debug :
    print(json.dumps(loginArray,indent = 4))
    print(json.dumps(loginResponse,indent = 4))

#quit if something is wrong with the login
if loginResponse["statuscode"] != 2000:
    exit(loginResponse)

#build the remaining payloads
standardArray["param"]["apisessionid"] = loginResponse["responsedata"]["apisessionid"]
logoutArray = payloadbuilder("logout")

standardArray["param"]["domainname"] = domain
infoDnsRecordsArray = payloadbuilder("infoDnsRecords")
updateDnsRecordsArray = payloadbuilder("updateDnsRecords")

logout = json.dumps(logoutArray)
infoDnsRecords=json.dumps(infoDnsRecordsArray)

#get current dns records
infoDnsRecordsResponse = call_api(infoDnsRecords)
infoDnsRecords=infoDnsRecordsResponse["responsedata"]["dnsrecords"]

if debug:
    print(json.dumps(infoDnsRecordsArray,indent = 4))
    print(json.dumps(infoDnsRecordsResponse,indent = 4))

#set the new entry
newRecords = []

#if deleting an entry, do not add a new record
if mode == "add":
    newRecords.append({})
    newRecords[0] = {}
    newRecords[0]["hostname"] = host
    newRecords[0]["type"] = entrytype
    newRecords[0]["priority"] = "0"
    newRecords[0]["deleterecord"] = False
    newRecords[0]["destination"] = new_destination
    newRecords[0]["state"] = "yes"

if mode == "remove" or mode == "update":

    #search for the correct entries to be deleted/updated
    for x in range(len(infoDnsRecords)):
        if (infoDnsRecords[x]["hostname"] == host) and (infoDnsRecords[x]["type"] == entrytype):
            #if the destination is not set, update all/remove all
            if current_destination:
                if infoDnsRecords[x]["destination"] == current_destination:
                    newRecords.append(infoDnsRecords[x])
            else:
                newRecords.append(infoDnsRecords[x])
    
    for x in range(len(newRecords)):
        
        if mode="remove":
            newRecords[x]["deleterecord"] = True
        if mode="update":
            newRecords[x]["destination"] = new_destination


#update DNS only, if there is something to update
if len(newRecords)!=0:
    #add the dnsrecords to the JSON
    updateDnsRecordsArray["param"]["dnsrecordset"] = {}
    updateDnsRecordsArray["param"]["dnsrecordset"]["dnsrecords"] = []
    updateDnsRecordsArray["param"]["dnsrecordset"]["dnsrecords"] = newRecords
    updateDnsRecords = json.dumps(updateDnsRecordsArray)

    #update DNS
    updateDnsRecordsResponse = call_api(updateDnsRecords) 
    
    if debug:
        print(json.dumps(updateDnsRecordsArray,indent = 4))
        print(json.dumps(updateDnsRecordsResponse,indent = 4))
    
    if updateDnsRecordsResponse["statuscode"] != 2000:
        print("Error updating DNS records")
        print(updateDnsRecordsResponse["longmessage"])
else:
    if debug:
        print("No update required.")

#logout
logoutResponse = call_api(logout)
if debug:
    print("Script ended.")

