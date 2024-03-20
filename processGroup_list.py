#!/usr/bin/env python
import sys
from argparse import ArgumentParser
import csv
from dynatrace_api import DynatraceApi
import logging
import logging.config
from datetime import datetime
logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("--debug", dest="debug", help="Set log level to debbug", action='store_true')
parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')
parser.add_argument("-f", "--file", dest="file", help="Filename for output, default is processGroup_list.csv", default="processGroup_list.csv")

parser.add_argument("--tag", dest="tag", help="Process Group Tag to filter by")
parser.add_argument("--mz", dest="mz", help="Management Zone to filter by")
parser.add_argument("--host", dest="host", help="Host to filter by")
parser.add_argument("--name", dest="name", help="Filters by the name of the PG, uses a startswith logic")


args = parser.parse_args()

env = args.environment
apiToken = args.token
verifySSL = not args.insecure
debug = args.debug

fileName = args.file

tag = args.tag
mz = args.mz
host = args.host
name = args.name

if debug:
    logging.getLogger().setLevel(logging.DEBUG)

logging.info("="*200)
logging.info("Running %s ", " ".join(sys.argv))
logging.info("="*200)

#processTypes = ['DOTNET', 'IIS_APP_POOL', 'JAVA', 'NODE_JS', 'PHP']
#CLV and RAP only support JAVA at the moment
processTypes = "JAVA"

dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

def getSelectorURL():

    url = "/api/v2/entities?pageSize=500&entitySelector=type(PROCESS_GROUP)"
    url += f",softwareTechnologies({processTypes})"

    if mz:
        url += ",mzName(" + mz + ")"
    if tag:
        url += ",tag(" + tag + ")"
    if host:
        url += ",fromRelationships.runsOn(entityId(" + host + "))"
    if name:
         url += ",entityName.startsWith(" + name + ")"
    url += "&fields=+fromRelationships,+properties,+managementZones&from=now-365d"

    return url

print("start")

url = getSelectorURL()
#processGroups = dynatraceApi.getAllEntities('/api/v2/entities?pageSize=500&&fields=+managementZones&entitySelector=type("PROCESS_GROUP"),mzName("EasyTrade","AppSec: Unguard","Cloud: Google"),softwareTechnologies("JAVA")&from=now-2h')

#processGroups = dynatraceApi.getAllEntities('/api/v2/entities?pageSize=500&&fields=+managementZones&entitySelector=type(PROCESS_GROUP),softwareTechnologies(JAVA)&from=now-365d')

#processGroups = dynatraceApi.getAllEntities('/api/v2/entities?pageSize=500&&fields=+fromRelationships,+properties,+managementZones&entitySelector=type(PROCESS_GROUP),mzName(allservers),softwareTechnologies(JAVA)')
#processGroups = dynatraceApi.getAllEntities('/api/v2/entities?pageSize=500&entitySelector=type(PROCESS_GROUP),softwareTechnologies(JAVA),mzName(allservers)&fields=+fromRelationships,+properties,+managementZones')
processGroups = dynatraceApi.getAllEntities(url)


print(url)

with open(fileName, "w", newline='') as f:
    writer = csv.writer(f)
    
    for pg in processGroups:
        print(pg["entityId"])
        writer.writerow([pg["entityId"]])

print("end")