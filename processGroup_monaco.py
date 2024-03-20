#!/usr/bin/env python
import sys
import os
import argparse
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
#parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to create the monaco manifest", required=True)
#parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("--debug", dest="debug", help="Set log level to debug", action='store_true')
parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')
parser.add_argument('-f', '--file', help="CSV file containing the Process Group in the first column (no header)")
parser.add_argument('-m', '--monaco', help="Folder to place the monaco configuration in, defaults to monaco in the local folder", default="monaco")
parser.add_argument('-p', '--project', help="Project name for the monaco configuration, defaults to appsec", default="appsec")
parser.add_argument('--clv', help="Include Code-level vulnerabilities configuration in monaco projection, defaults to true", action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--rap', help="Include Runtime Application Protection configuration in monaco projection, defaults to true", action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--oaf', help="Include OneAgent Features configuration in monaco projection, defaults to false", action=argparse.BooleanOptionalAction, default=False)



args = parser.parse_args()

#env = args.environment
#apiToken = args.token
verifySSL = not args.insecure
debug = args.debug
filename = args.file
monacoFolder = args.monaco
projectFolder = args.project
includeCLV = args.clv
includeRAP = args.rap
includeOAF = args.oaf



if debug:
    logging.getLogger().setLevel(logging.DEBUG)

logging.info("="*200)
logging.info("Running %s ", " ".join(sys.argv))
logging.info("="*200)


#dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

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

def createOAF_json():
    JAVA_CASP_FLAW_FINDER_IAST = {"enabled": True,
        "key": "JAVA_CASP_FLAW_FINDER_IAST"
    }

    SENSOR_JAVA_CASP_FLAW_FINDER = {"enabled": True,
        "instrumentation": True,
        "key": "SENSOR_JAVA_CASP_FLAW_FINDER"
    }

    filename = monacoFolder + "/" + projectFolder + "/java-code-level-vulnerability-evaluation.json"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w', newline='') as f:
        f.write(json.dumps(JAVA_CASP_FLAW_FINDER_IAST, indent=4))
    
    filename = monacoFolder + "/" + projectFolder + "/java-code-level-attack-evaluation.json"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w', newline='') as f:
        f.write(json.dumps(SENSOR_JAVA_CASP_FLAW_FINDER, indent=4))

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

def appendOAFConfig(processGroup, schema, template, function):
    #print(processGroup)
    config = f"""
    - id: id_{function}_{processGroup}
      type:
        settings:
          schema: {schema}
          scope: {processGroup}
      config:
        name: {function}_{processGroup}
        template: {template}
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
print(includeCLV)
if includeCLV:
    print("here")
    logging.info("Creating Code-level vulnerabilities JSON file.")
    createCLV_json()

if includeRAP:
    logging.info("Creating Runtime Application Protection JSON file.")
    createRAP_json()


if includeOAF:
    logging.info("Creating OneAgent Feature JSON files.")
    createOAF_json()

createConfig()

for pg in pgIds:
    print(pg)
    if includeCLV:
        logging.info("Creating Code-level vulnerabilities configuration.")
        appendConfig(pg, "builtin:appsec.code-level-vulnerability-rule-settings", "code-level-vulnerability-rule.json", "clv")
    if includeRAP:
        logging.info("Creating Runtime Application Protection configuration.")
        appendConfig(pg, "builtin:appsec.attack-protection-advanced-config", "attack-protection-advanced-rule.json", "rap")
    if includeOAF:
        logging.info("Creating OneAgent Feature configuration.")
        appendOAFConfig(pg, "builtin:oneagent.features", "java-code-level-vulnerability-evaluation.json", "oaf_vul")
        appendOAFConfig(pg, "builtin:oneagent.features", "java-code-level-attack-evaluation.json", "oaf_attack")



print("end")