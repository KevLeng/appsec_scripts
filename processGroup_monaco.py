#!/usr/bin/env python
import sys
import os
from argparse import ArgumentParser
import csv
from dynatrace_api import DynatraceApi
import logging
import logging.config
from datetime import datetime
import json

logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("--debug", dest="debug", help="Set log level to debug", action='store_true')
parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')
parser.add_argument('-f', '--file', help="CSV file containing the Process Group in the first column (no header)")
parser.add_argument('-m', '--monaco', help="Folder to place the monaco configuration in, defaults to monaco in the local folder", default="monaco")
parser.add_argument('-p', '--project', help="Project name for the monaco configuration, defaults to appsec", default="appsec")


args = parser.parse_args()

env = args.environment
apiToken = args.token
verifySSL = not args.insecure
debug = args.debug
filename = args.file
monacoFolder = args.monaco
projectFolder = args.project


if debug:
    logging.getLogger().setLevel(logging.DEBUG)

logging.info("="*200)
logging.info("Running %s ", " ".join(sys.argv))
logging.info("="*200)

for t in sys.argv:
    print(t)
dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

def createManifest():
    content = f"""manifestVersion: 1.0
    
projects:
    - name: {projectFolder}
      path: {projectFolder}

environmentGroups:
    - name: target
      environments:
        - name: target-environment
          url:
            type: environment
            value: DT_TENANT_URL
          auth:
            token:
              name: DT_API_TOKEN
    """
    filename = monacoFolder + "/manifest.yaml"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w', newline='') as f:
        f.write(content)

def createCLV_json():
    clv_json = {
        "enabled": True,
        "criteria": {
          "processGroup": "{{ .PGId }}"
        },
        "vulnerabilityDetectionControl": {
          "monitoringMode": "MONITORING_ON"
        },
        "metadata": {
          "comment": "Created by monaco"
        }
    }
    filename = monacoFolder + "/" + projectFolder + "/code-level-vulnerability-rule.json"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w', newline='') as f:
        f.write(json.dumps(clv_json, indent=4))

def createRAP_json():
    rap_json = {
        "enabled": True,
        "criteria": {
          "processGroup":  "{{ .PGId }}",
          "attackType": "ANY"
        },
        "attackHandling": {
          "blockingStrategy": "MONITOR"
        },
        "metadata": {
          "comment": "Created by monaco"
        }
    }

    filename = monacoFolder + "/" + projectFolder + "/attack-protection-advanced-rule.json"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w', newline='') as f:
        f.write(json.dumps(rap_json, indent=4))

def createConfig():

    config = "configs:"

    filename = monacoFolder + "/" + projectFolder + "/_config.yaml"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w', newline='') as f:
        f.write(config)

def appendConfig(processGroup, schema, template, function):
    #print(processGroup)
    config = f"""
    - id: id_{function}_{processGroup}
      type:
        settings:
          schema: {schema}
          scope: environment
      config:
        name: {function}_{processGroup}
        template: {template}
        parameters:
          {function.upper()}Enabled: 
            name: {function.upper()}ENABLED
            type: environment
            default: true
          PGId: {processGroup}
    """
    filename = monacoFolder + "/" + projectFolder + "/_config.yaml"
    with open(filename, "a", newline="") as f:
        f.write(config)

print("start")

if filename:
    pgIds = []
    with open(filename, newline='') as csvfile:
        filereader = csv.reader(csvfile, delimiter=',', quotechar='|')
        for row in filereader:
            pgIds.append(row[0])
            
createManifest()
createCLV_json()
createRAP_json()
createConfig()

for pg in pgIds:
    print(pg)
    appendConfig(pg, "builtin:appsec.code-level-vulnerability-rule-settings", "code-level-vulnerability-rule.json", "clv")
    appendConfig(pg, "builtin:appsec.attack-protection-advanced-config", "attack-protection-advanced-rule.json", "rap")


print("end")