#!/usr/bin/env python
import pandas as pd
import json
import copy
from argparse import ArgumentParser
from dynatrace_api import DynatraceApi


# get the Dynatrace Environment (URL) and the API Token with arguments
# with the details parameter, the details for each security problem are fetched
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')


args = parser.parse_args()

env = args.environment
apiToken = args.token
verifySSL = not args.insecure

def writeResultToFile(filename, result):
    df = pd.DataFrame(result)

    # remove duplicates
    df = df.drop_duplicates()

    df.to_csv(filename,sep=';', index=False, quotechar="'", encoding='utf-8')
    print()
    print('results stored under softwareComponent_PGI_CGI.csv')

dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

def getData(loadFromFile, api, filename):

    if loadFromFile:
        print(f"Loading data from file {filename}")
        with open(filename, 'r') as file:
            data = json.load(file)
        
        return data

    else:
        print(f"Calling Dynatrace API {api}")
        result  = dynatraceApi.getAllEntities(api)
        with open(filename, 'w') as file:
            json.dump(result, file, indent=4)
        
        print(f"Number of results: {len(result)}")
        return result
        

loadDataFromFiles = False

softwareComponents = getData(loadDataFromFiles, '/api/v2/entities?fields=+properties.softwareComponentType,+properties.packageName,+properties.softwareComponentVersion,+fromRelationships.isSoftwareComponentOfPgi&pageSize=500&entitySelector=type(SOFTWARE_COMPONENT)', 'softwareComponents.json')
#softwareComponents = dynatraceApi.getAllEntities('/api/v2/entities?fields=+properties.softwareComponentType,+properties.packageName,+properties.softwareComponentVersion,+fromRelationships.isSoftwareComponentOfPgi&pageSize=500&entitySelector=type(SOFTWARE_COMPONENT),entityId(SOFTWARE_COMPONENT-00282CEED2E6A288)')
#softwareComponents = dynatraceApi.getAllEntities('/api/v2/entities?fields=+properties.softwareComponentType,+properties.packageName,+properties.softwareComponentVersion,+fromRelationships.isSoftwareComponentOfPgi&pageSize=500&entitySelector=type(SOFTWARE_COMPONENT)')

pgInstance = getData(loadDataFromFiles, '/api/v2/entities?fields=+fromRelationships.isPgiOfCgi&pageSize=500&entitySelector=type(PROCESS_GROUP_INSTANCE)', 'processGroupInstance.json')
#pgInstance = dynatraceApi.getAllEntities('/api/v2/entities?fields=+fromRelationships.isPgiOfCgi&pageSize=500&entitySelector=type(PROCESS_GROUP_INSTANCE),entityId(PROCESS_GROUP_INSTANCE-B3A710513DAD82BB,PROCESS_GROUP_INSTANCE-D5EE7D3C6771D42B)')
#pgInstance = dynatraceApi.getAllEntities('/api/v2/entities?fields=+fromRelationships.isPgiOfCgi&pageSize=500&entitySelector=type(PROCESS_GROUP_INSTANCE)')

cgInstance = getData(loadDataFromFiles, '/api/v2/entities?fields=+properties.containerImageName&pageSize=500&entitySelector=type(CONTAINER_GROUP_INSTANCE)', 'containerGroupInstance.json')
#cgInstance = dynatraceApi.getAllEntities('/api/v2/entities?fields=+properties.containerImageName&pageSize=500&entitySelector=type(CONTAINER_GROUP_INSTANCE),entityId(CONTAINER_GROUP_INSTANCE-F713909ADD2D62A2,CONTAINER_GROUP_INSTANCE-166AAB7E66F5141A)')
#cgInstance = dynatraceApi.getAllEntities('/api/v2/entities?fields=+properties.containerImageName&pageSize=500&entitySelector=type(CONTAINER_GROUP_INSTANCE)')


masterList = []


for component in softwareComponents:
    listEntry = {}

    listEntry['softwareComponentType'] = component.get('properties', {}).get('softwareComponentType', '')
    listEntry['packageName'] = component.get('properties', {}).get('packageName', '')
    listEntry['softwareComponentVersion'] = component.get('properties', {}).get('packageName', '')
    listEntry['softwareComponentdisplayName'] = component['displayName']
    
    #print(f"Software Component: {component['displayName']}, ID: {component['entityId']}")
    #print(component)

    # loop through pgi's of software component
    for relProcessGroupInstance in component.get('fromRelationships', {}).get('isSoftwareComponentOfPgi', []):

        #print(relProcessGroupInstance)
        #print(relProcessGroupInstance.get('id'))

        # look for pgi in full pgi list
        foundPGI = False
        for pgi in pgInstance:
            #print(pgi)
            #print("pgi id")
            #print(pgi.get('entityId'))
            pgidisplayName = ''
            if relProcessGroupInstance.get('id') == pgi.get('entityId'):
                foundPGI = True
                #print("pgi match")
                pgidisplayName = pgi.get('displayName')
                #print(f"PGI display name {pgidisplayName}")
                       
                # loop through containers of pgi
                for relContainer in pgi.get('fromRelationships', {}).get('isPgiOfCgi', []):
                    #print("relContainer")
                    #print(relContainer)
                    foundContainer = False
                    containerImageName = ''
                    cgidisplayName = ''

                    # look for cgi in full cgi list
                    for cgi in cgInstance:
                        #print(cgi)
                        #print(cgi.get('entityId'))

                        if relContainer.get('id') == cgi.get('entityId'):
                            foundContainer = True
                            #print("cgi match")
                            cgidisplayName = cgi.get('displayName')
                            containerImageName = cgi.get('properties', {}).get('containerImageName', '')

                            #containerImageName = ""
                            #if 'containerImageName' in cgi['properties']:
                            #    containerImageName = cgi['properties']['containerImageName']
                            #print(f"Software Component: {component['displayName']}, Process Group Instance: {pgi['displayName']}, Container Group Instance: {cgi['displayName']}, Container Image: {containerImageName}")    
                            break
                    
                    if not foundContainer:
                        print(f"unable to find container {relContainer.get('id')} for process {relProcessGroupInstance.get('id')} software {component.get('id')}")

                    listEntry['ContainerGroupInstance_displayName'] = cgidisplayName
                    listEntry['containerImageName'] = containerImageName
                #print(f"PGI display name 2 {pgidisplayName}")
                listEntry['ProcessGroupInstance_displayName'] = pgidisplayName
                #print(f"listEntry {listEntry}")
                masterList.append(copy.deepcopy(listEntry))
                #print(f"masterList {masterList}")
                break


print(f"The length masterList {len(masterList)}")

writeResultToFile('softwareComponent_PGI_CGI.csv', masterList)
