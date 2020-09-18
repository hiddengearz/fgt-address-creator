import requests
import csv
import os
import json
import sys

usersFile = ""
showHelp = False
_ip = False
_dns = False
firewall = ""
group = ""
token = ""

for i, arg in enumerate(sys.argv):
    if '-h' in arg or '-help' in arg:
        showHelp = True
    elif '-f' == arg or '-file' == arg:
        usersFile = str(sys.argv[i+1])
    elif '-ip' in arg:
        _ip = True
    elif '-dns' in arg:
        _dns = True
    elif '-fw' == arg:
        firewall = str(sys.argv[i+1])
    elif '-g' == arg:
        group = str(sys.argv[i+1])
    elif '-t' == arg:
        token = str(sys.argv[i+1])


if showHelp:
    print("-f, --filename <filename.csv> The csv must have 4 columns column A for Object Name, column B for Interface, Column C for IP (optional, leave blank if not needed) and Column D for DNS (optional, leave blank if not needed)" +
    "The first row will be ignored as I assume it's headers e.g Hostname, Interface, IP & DNS")
    print("-fw The IP:Port for firewall e.g 1.1.1.1:1234")
    print("-ip When creating the object use the IP address in column C")
    print("-dns When creating the object use the dns address in column d")
    print("-g the group to add all of the objects to (optional)")
    print("-t provide an API key for authentication")

elif _ip and _dns:
    print("Please choose IP or DNS, not both.")

elif not _ip and not _dns:
    print("Please choose IP or DNS")

elif usersFile == "":
    print("Please choose a file")

elif token == "":
    print("Please provide an API key")

elif firewall == "":
    print("Please provide an IP & port for the firewall")

else:
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36'}
    completed = []
    errors = []
    interfaces = []
    groups = []
    addToGroup = []

    path = os.getcwd()

    with open(usersFile, newline='') as f:
        reader = csv.reader(f)
        csvData = list(reader)

    url = "https://" + firewall + "/api/v2/cmdb/firewall/address?access_token=" + token
    resp = requests.get(url, verify=False, headers=headers)
    existingHosts = resp.json()

    urlInterface = "https://" + firewall + "/api/v2/cmdb/system/interface?access_token=" + token
    respInterface = requests.get(urlInterface, verify=False, headers=headers)
    interfacesJson = respInterface.json()
    if respInterface.status_code == 200:
        for data in interfacesJson["results"]:
            interfaces.append(data["name"])
    
    urlZones = "https://" + firewall + "/api/v2/cmdb/system/zone?access_token=" + token
    respZones = requests.get(urlZones, verify=False, headers=headers)
    ZonesJson = respZones.json()
    if respZones.status_code == 200:
        for data in ZonesJson["results"]:
            interfaces.append(data["name"])
    

    urlGroups = "https://" + firewall + "/api/v2/cmdb/firewall/addrgrp?access_token=" + token
    respGroups = requests.get(urlGroups, verify=False, headers=headers)
    GroupsJson = respGroups.json()
    if respGroups.status_code == 200:
        for data in GroupsJson["results"]:
            groups.append(data["name"])

    if resp.status_code == 200: #if the first request was sucessful... It really should if all requests are sucessfull 

        for i, newHost in enumerate(csvData): #for each host from the csv
            payload = {}
            if i > 0: #ignore the first line as it's headers
                name = ""
                ip = ""
                dns = ""
                _type = ""
                createObject = True
                for item in existingHosts["results"]: # for each host host/object from the firewall.. doing this to compare so we don't create duplicate objects
                    if len(newHost) > 2: #if row in the csv has atleast 3 columns (object name, interface & IP)
                        if newHost[0] != "": #If column A has a hostname
                            name = newHost[0]
                            if name.lower() in item["name"].lower(): #if newhost name already exists don't create object
                                errors.append("Warning: Couldn't create object: " + newHost[0] +" object already exists. Using existing object " + item["name"] + " instead")
                                addToGroup.append(item["name"]) #still add the existing object to the new group from -g tho
                                createObject = False #don't create the object & break out of loop to save resources
                                break
                            else: #else create a new object
                                payload["name"] = name #paylod is the POST paramaters for the new object
                                if newHost[1] in interfaces: #If the interface in column B exists
                                    payload["associated-interface"] = newHost[1]
                                else: #else don't create the object & update the error log
                                    errors.append("Error: interface " + newHost[1] + " doesn't exist. Check capitalization? Failed to add " + newHost[0])
                                    createObject = False #don't create the object & break out of loop to save resources
                                    break

                            if createObject and newHost[2] != "": #If column b has a ip
                                ip = newHost[2]
                                if "subnet" == item:
                                    if ip == item["subnet"]: #if newhost subnet already exists don't create object
                                        errors.append("Warning: Couldn't create object: " + newHost[2] +" subnet already exists. Using existing object " + item["name"] + " instead")
                                        addToGroup.append(item["name"]) #still add the existing object to the new group from -g tho
                                        createObject = False #don't create the object & break out of loop to save resources
                                        break
                                if _ip and createObject: #if -ip add the ip to the payload
                                    payload["subnet"] = ip
                                    payload["type"] = "ipmask"
                        else:
                            errors.append("Warning: Couldn't create object: " + newHost[0] +" name is blank.")
                            createObject = False
                            break
                        
                        if len(newHost) > 3: #If a DNS/IP is provided continue, either the DNS or IP ill be added to the payload depending on if -ip or -dns was selected
                            if createObject and newHost[3] != "": #If column b has a fqdn
                                if "wildcard-fqdn" == item: #if dns already exists
                                    dns = newHost[3]
                                    if dns.lower() == item["wildcard-fqdn"].lower(): #if fqdn name already exists don't create object
                                        errors.append("Warning: Couldn't create object: " + newHost[3] +" wildcard fqdn already exists. Using existing object " + item["name"] + " instead")
                                        addToGroup.append(item["name"]) #still add the existing object to the new group from -g tho
                                        createObject = False
                                        break
                                elif "fqdn" == item: #if dns already exists
                                    dns = newHost[3]
                                    if dns.lower() == item["fqdn"].lower(): #if newhost dns already exists don't create object
                                        errors.append("Warning: Couldn't create object: " + newHost[3] +" fqdn already exists. Using existing object " + item["name"] + " instead")
                                        addToGroup.append(item["name"]) #still add the existing object to the new group from -g tho
                                        createObject = False
                                        break
                                
                                dns = newHost[3]
                                if "*" in dns and _dns and createObject: #if -dns and * in the dns add a wildcard fqdn payload
                                    payload["wildcard-fqdn"] = dns
                                    payload["type"] = "wildcard-fqdn"

                                elif _dns and createObject: #if -dns add the dns to payload
                                    payload["fqdn"] = dns
                                    payload["type"] = "fqdn"
                                    
                if createObject: #After cross checking the new object from the csv with existing objects on the FW if there is no duplicates create the object
                    addToGroup.append(payload["name"]) #add the new object to the group in -g
                    resp2 = requests.post(url, json=payload, verify=False, headers=headers)
                    if resp2.status_code == 200: #update list of completed objects
                        completed.append(str(payload) + " added succesfully!")
                    else: #update error list
                        errors.append ("Error: " + str(payload) + " failed to add")
        
        if group != "": #if -g was provided
            payload = {} #payload is the HTTP POST paramaters for creating the new group on the FW
            payload["name"] = group
            payload["member"] = []
            for host in addToGroup: #add each object to the payload
                payload["member"].append({'name': host})
            resp2 = requests.post(urlGroups, json=payload, verify=False, headers=headers)
            if resp2.status_code == 200: #update completed list
                completed.append(str(payload) + " added succesfully!")
            else: #update error list
                errors.append ("Error: " + str(payload) + " failed to add")

        print("\n\n\n\n####Results###")
        for success in completed: #print results
            print("Added: " + success)             
        for error in errors: #print errors
            print(error)

