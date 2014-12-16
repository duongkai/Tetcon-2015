#!/usr/bin/env python

from os import sys
import json
import requests
from time import sleep

API = "https://api.dev.ssllabs.com/api/fa78d5a4"
SLEEP_TIME = 15

def analyze (hostname):
   # submit request
    analyze_url = "{API}/analyze?host={hostname}&publish=off&all=done".format (API=API, hostname=hostname)
    # initializing the request without cache
    req = requests.get (analyze_url + "&clearCache=on")
    print analyze_url + "&clearCache=on"
    sleep (SLEEP_TIME)
    while (True):
        print analyze_url
        req = requests.get (analyze_url)
        #print "raw response: " + req.text
        data = json.loads (req.text)
        status = data[u"status"]
        hostname = data[u"host"]
        if status == "DNS":
            status_message = data[u"statusMessage"]
            status_details = "DNS_RESOLVING"
        elif status == "READY":
            return req.text
        else: # IN_PROGRESS
            status_details = data[u"endpoints"][0][u"statusDetails"]
            status_message = data[u"endpoints"][0][u"statusDetailsMessage"]
            progress = data[u"endpoints"][0][u"progress"]
        print "Checking: {host}. Status: {status}. Progress: {progress}".format (host=hostname, status=status, progress=progress)
        print "  Testing: {details}. Message: {msg}".format (details=status_details, msg=status_message)
        sleep (SLEEP_TIME)

def extract_proto (protocols):
    s = ""
    for pro in protocols:
        s += pro[u"name"] + ": " + pro[u"version"] + "\t"
    return s

def process_data (response_text):
    data = json.loads (response_text)
    # write down raw response
    hostname = data[u"host"]
    print "Analyzing: " + hostname + "..."
    with open(hostname + "-raw.log", "w") as fout:
        fout.write (response_text)
    # traverse all endpoints and get the best possible result
    servers = data[u"endpoints"]
    for server in servers:
        # ready report
        if server[u"statusMessage"] == "Ready":
            # Extract grade, hasWarnings, key["size"], key["sigAlg"], key["issuerLabel"], 
            # protocols, supportsRc4
            # stsResponseHeader, pkpResponseHeader 
            # vulnBeast, poodleTls, openSslCcs, heartbleed
            grade = server[u"grade"]
            # Mismatch Certificates. No check
            if grade == "M":
                break
            ip = server[u"ipAddress"]
            warnings = server[u"hasWarnings"]
            details = server[u"details"]
            key_size = details[u"key"][u"size"]
            sign_alg = details[u"cert"][u"sigAlg"]
            issuer = details[u"cert"][u"issuerLabel"]
            # protocols
            protocols = extract_proto (details[u"protocols"])
            rc4_support = details[u"supportsRc4"]
            # vulnerable
            beast = details[u"vulnBeast"]
            poodle = details[u"poodleTls"]
            ccs = details[u"openSslCcs"]
            heartbleed = details[u"heartbleed"]
            res = "Site: {hostname}. IP: {ip}. Grade: {grade}\n".format \
                (hostname=hostname, ip=ip, grade=grade)
            res += "\t Protocols: {pro}\n".format (pro=str (protocols))
            res += "\t Certificates: {issuer}. Key size: {size}. Sign Algorithm: {sign}\n".format \
                (issuer=issuer, size=key_size, sign=sign_alg)
            res += "\t Beast: {beast}. PoodleTLS: {poodle}. CCS: {ccs}. Heartbleed: {heartbleed}\n".format \
                (beast=beast, poodle=poodle, ccs=ccs, heartbleed=heartbleed)
            try: 
                hsts = server[u"stsResponseHeader"]
            except KeyError:
                hsts = "None"
            res += "\t HSTS: {0}\n".format (hsts)
            try:
                pin = server[u"pkpResponseHeader"]
            except KeyError:
                pin = "None"
            res += "\t Public key Pinning: {0}\n".format (pin)
            return res
    return None

#analyze ("ebank.msb.com.vn")
#print process_data (analyze ("apib1.anz.com"))

if __name__ == "__main__":
    filename = sys.argv[1]
    with open (filename, "r") as fin:
        domains = [line[:-1] for line in fin.readlines()]
        result = ""
        for domain in domains:
            tmp = process_data (analyze (domain))
            print tmp
            result += process_data (tmp)
    print "############################ Final #####################"
    print result