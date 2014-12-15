#!/usr/bin/env python

from os import sys
import json
import requests
from time import sleep

API = "https://api.dev.ssllabs.com/api/fa78d5a4"

def analyze (hostname):
    # submit request
    print "  Submitting request"
    target = API + "/analyze?"
    req = requests.get (target + "host={}&".format (hostname) + "clearCache=on&publish=off")
    # sleeping for resolving request
    sleep (5)
    # re-submit to get the IP address
    print "  Re-submit"
    req = requests.get (target + "host={}&".format (hostname) + "clearCache=on&publish=off")
    pi = 0
    if hostname == "www.seanet.vn":
        pi = -1
    while (True):
        try:
            ip = json.loads (req.text)[u'endpoints'][pi][u'ipAddress']
            break
        except KeyError:
            print ("Unexpected failure! Sleep and Retry")
            print req.text
            sleep (15)
    print "    IP resolv: " + ip
    print "  Sleeping"
    # Print get the grade
    #print "  Getting the Grade"
    endpoint = API + "/getEndpointData?"
    urlReq = endpoint + "host={0}&s={1}&fromCache=off".format (hostname, ip)
    while (True):
        sleep (30)
        req = requests.get (urlReq)
        try:
            # try to get the grade
            grade = json.loads (req.text)[u'grade']
            break
        except KeyError:
            try:
                response = json.loads (req.text)
                status_message = response['statusMessage']
                progress = response['progress']
                status_details = response['statusDetails']
                print "Status: {0}, details: {1}, progress {2}".format (status_message, status_details, progress)
            except KeyError:
                print req.text, urlReq
                print "Unexpected failure. Sleep and Rretry"
                sleep (15)
    return grade, req.text

if __name__ == "__main__":
    filename = sys.argv[1]
    #log = "scan_20151215.log"
    with open (filename, "r") as fin:
        domains = [line[:-1] for line in fin.readlines()]
        for domain in domains:
            print "checking domain {}".format (domain)
            data = analyze (domain)
            print "Grade: " + data[0]
            with open (domain + ".log", "w") as fout:
                fout.write (data[1] + "\n")

