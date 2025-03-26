#!/usr/bin/env python
import sys
import pandas as pd
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


print("Getting all softwareComponents....")

#softwareComponents = dynatraceApi.getAllEntities('/api/v2/entities?fields=+properties.softwareComponentType,+properties.packageName,+properties.softwareComponentVersion,+fromRelationships.isSoftwareComponentOfPgi&pageSize=500&entitySelector=type(SOFTWARE_COMPONENT),entityId(SOFTWARE_COMPONENT-00282CEED2E6A288)')
softwareComponents = dynatraceApi.getAllEntities('/api/v2/entities?fields=+properties.softwareComponentType,+properties.packageName,+properties.softwareComponentVersion,+fromRelationships.isSoftwareComponentOfPgi&pageSize=500&entitySelector=type(SOFTWARE_COMPONENT)')

print("...softwareComponents complete")
print(f"Number of softwareComponents: {len(softwareComponents)}")

print("Getting all process group instances....")
#pgInstance = dynatraceApi.getAllEntities('/api/v2/entities?fields=+fromRelationships.isPgiOfCgi&pageSize=500&entitySelector=type(PROCESS_GROUP_INSTANCE),entityId(PROCESS_GROUP_INSTANCE-B3A710513DAD82BB,PROCESS_GROUP_INSTANCE-D5EE7D3C6771D42B)')
pgInstance = dynatraceApi.getAllEntities('/api/v2/entities?fields=+fromRelationships.isPgiOfCgi&pageSize=500&entitySelector=type(PROCESS_GROUP_INSTANCE)')

print("...process group instances complete")
print(f"Number of process group instances: {len(pgInstance)}")

print("Getting all container group instances....")
#cgInstance = dynatraceApi.getAllEntities('/api/v2/entities?fields=+properties.containerImageName&pageSize=500&entitySelector=type(CONTAINER_GROUP_INSTANCE),entityId(CONTAINER_GROUP_INSTANCE-F713909ADD2D62A2,CONTAINER_GROUP_INSTANCE-166AAB7E66F5141A)')
cgInstance = dynatraceApi.getAllEntities('/api/v2/entities?fields=+properties.containerImageName&pageSize=500&entitySelector=type(CONTAINER_GROUP_INSTANCE)')

print("...container group instances complete")
print(f"Number of container group instances: {len(cgInstance)}")

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
        for pgi in pgInstance:
            #print(pgi)
            #print("pgi id")
            #print(pgi.get('entityId'))
            pgidisplayName = ''
            if relProcessGroupInstance.get('id') == pgi.get('entityId'):
                #print("pgi match")
                pgidisplayName = pgi.get('displayName')

                # loop through containers of pgi
                for relContainer in pgi.get('fromRelationships', {}).get('isPgiOfCgi', []):
                    #print("relContainer")
                    #print(relContainer)

                    containerImageName = ''
                    cgidisplayName = ''

                    # look for cgi in full cgi list
                    for cgi in cgInstance:
                        #print(cgi)
                        #print(cgi.get('entityId'))

                        if relContainer.get('id') == cgi.get('entityId'):
                            #print("cgi match")
                            cgidisplayName = cgi.get('displayName')
                            containerImageName = cgi.get('properties', {}).get('containerImageName', '')

                            #containerImageName = ""
                            #if 'containerImageName' in cgi['properties']:
                            #    containerImageName = cgi['properties']['containerImageName']
                            #print(f"Software Component: {component['displayName']}, Process Group Instance: {pgi['displayName']}, Container Group Instance: {cgi['displayName']}, Container Image: {containerImageName}")    
                            break

                    listEntry['ContainerGroupInstance_displayName'] = cgidisplayName
                    listEntry['containerImageName'] = containerImageName

                listEntry['ProcessGroupInstance_displayName'] = pgidisplayName

                masterList.append(listEntry)
                break


print(f"The length masterList {len(masterList)}")
writeResultToFile('softwareComponent_PGI_CGI.csv', masterList)
