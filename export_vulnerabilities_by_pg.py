#!/usr/bin/env python
import sys
from argparse import ArgumentParser
from datetime import datetime
from dynatrace_api import DynatraceApi
import csv
import logging
import logging.config
logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
# with the details parameter, the details for each security problem are fetched
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("--debug", dest="debug", help="Set log level to debbug", action='store_true')

parser.add_argument("-d", "--details", dest="details", help="Fetch the details for each security problem (takes longer)", action='store_true')
parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')

args = parser.parse_args()

env = args.environment
apiToken = args.token
showDetails = args.details
verifySSL = not args.insecure

debug = args.debug

if debug:
    logging.getLogger().setLevel(logging.DEBUG)

logging.info("="*200)
logging.info("Running %s ", " ".join(sys.argv))
logging.info("="*200)

dynatraceApi = DynatraceApi(env, apiToken, verifySSL)
results = {}

# retireve all security problems
securityProblems = dynatraceApi.getThirdPartySecurityProblems()

for secP in securityProblems:
    remediationItems = dynatraceApi.getRemediationItems(secP)
    for remediationItem in remediationItems:
        pgId = remediationItem["id"]
        if not pgId in results:
            results[remediationItem["id"]] = []
        results[remediationItem["id"]].append({"remediationItem": remediationItem, "securityProblem": secP})

with open('vulnerabilities_by_pg.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    # header
    header = ['process.name', 'process.id', 'status', 'CVE', 'Vulnerability', 'package', 'displayId', 'firstSeen', 'lastDetected']
    writer.writerow(header)
    for pg in results:
        for result in results[pg]:
            remediationItem = result["remediationItem"]
            securityProblem = result["securityProblem"]
            
            writer.writerow([
                remediationItem['name'], 
                pg, 
                remediationItem['vulnerabilityState'], 
                ','.join(securityProblem['cveIds']), 
                securityProblem['packageName'], 
                securityProblem['displayId'], 
                datetime.fromtimestamp(securityProblem['firstSeenTimestamp']/1000).strftime("%m-%d-%Y %H:%M:%S"),
                datetime.fromtimestamp(securityProblem['lastUpdatedTimestamp']/1000).strftime("%m-%d-%Y %H:%M:%S")
                ])
