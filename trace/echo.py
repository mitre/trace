'''

NOTICE

This module was solely developed under MITRE corporation internal funding project code 10AOH630-CA

Approved for Public Release; Distribution Unlimited. Public Release Case Number 20-1780. 

(c) 2020 The MITRE Corporation. ALL RIGHTS RESERVED.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

'''

import json

# This is the reference data data used for making ECHO threat rate predictions, based on the ECHO Data Analysis paper
threat_samples = [ 0, 27, 7, 22, 0, 26, 13, 11, 0, 8, 16, 0, 23, 0, 0, 19, 9, 0, 0 ]
total_threat_samples = 96

def expansion(node_data):
    # This calls the steps necessary to expand the internal echo models
    expand_data(node_data)
    build_internals(node_data)

def build_internals(node_data):
    # This function builds out the internal threat state nodes and threat concept edges based on the answers to the ECHO questions
    """
    Each ECHO threat concept is assigned an id number in order to relate it to the ECHO data

    Echo threat concept unique ids:
        1   Abuse of Native Code
        2   Abuse of Pivot Functions
        3   Authentication Implementation Flaw
        4   Change of Controlled Parameters (Free)
        5   Denial of Local Services
        6   Denial of Network Services
        7   Exploitation of Poor Memory Management
        8   Impersonation (Sometimes Free)
        9   Indicator / Alert Manipulation
        10  Injecting Faults
        11  Interface Device Use (Free)
        12  Interface Overload
        13  No Authentication (Free)
        14  No User Mode / Kernel Mode Differentiation (Free)
        15  Privilege Management Implementation Flaw
        16  Resource Manipulation
        17  Sensor Repurposing (Input, Free)
        18  Sensor Repurposing (Output, Free)

    Echo internal node unique ids:
        0   User Mode Execution
        1   Kernel Mode Execution
        Interface-dependent:
            0   Interface Access
    """

    node_data["expansion"]={"nodes":[],"edges":[]}

    # Add internal nodes and edges
    node_data["expansion"]["nodes"].append({
        "id":str(node_data["id"])+"-0",
        "label":"User Mode Execution"})
    node_data["expansion"]["nodes"].append({
        "id":str(node_data["id"])+"-1",
        "label":"Kernel Mode Execution"})

    if "q8" in node_data["trace data"]["echo"]:
        node_data["expansion"]["edges"].append({
            "id":str(node_data["id"])+"-14",
            "from":str(node_data["id"])+"-0",
            "to":str(node_data["id"])+"-1",
            "threat":{  "id": node_data["trace data"]["common"]+"-14",
                        "rate": get_rate(14, node_data["trace data"]["echo"]["q8"])},
            "label":"No User Mode / Kernel Mode Differentiation"})

    if "q8a" in node_data["trace data"]["echo"]:
        node_data["expansion"]["edges"].append({
            "id":str(node_data["id"])+"-7",
            "from":str(node_data["id"])+"-0",
            "to":str(node_data["id"])+"-1",
            "threat":{  "id": node_data["trace data"]["common"]+"-7",
                        "rate": get_rate(7, node_data["trace data"]["echo"]["q8a"])},
            "label":"Exploitation of Poor Memory Management"})

    if "q8b" in node_data["trace data"]["echo"]:
        node_data["expansion"]["edges"].append({
            "id":str(node_data["id"])+"-15",
            "from":str(node_data["id"])+"-0",
            "to":str(node_data["id"])+"-1",
            "threat":{  "id": node_data["trace data"]["common"]+"-15",
                        "rate": get_rate(15, node_data["trace data"]["echo"]["q8b"])},
            "label":"Privilege Management Implementation Flaw"})

    # Add incoming nodes and edges
    if "from" in node_data:
        for i in node_data["from"]:

            node_data["expansion"]["nodes"].append({
                "id":str(i["id"]) + "-" + str(node_data["id"]) + "-0",
                "label":"Interface Access"})

            if "echo" in i["trace data"]:

                if "q5" in i["trace data"]["echo"]:
                    node_data["expansion"]["edges"].append({
                        "id":str(i["id"])+"-13",
                        "from":i["from"],
                        "to":str(i["id"]) + "-" + str(node_data["id"]) + "-0",
                        "threat":{  "id": i["trace data"]["common"]+"-13",
                                    "rate": get_rate(13, i["trace data"]["echo"]["q5"])},
                        "label":"No Authentication"})

                if "q5a" in i["trace data"]["echo"]:
                    node_data["expansion"]["edges"].append({
                        "id":str(i["id"])+"-3",
                        "from":i["from"],
                        "to":str(i["id"]) + "-" + str(node_data["id"]) + "-0",
                        "threat":{  "id": i["trace data"]["common"]+"-3",
                                    "rate": get_rate(3, i["trace data"]["echo"]["q5a"])},
                        "label":"Authentication Implementation Flaw"})

                if "q5b" in i["trace data"]["echo"]:
                    node_data["expansion"]["edges"].append({
                        "id":str(i["id"])+"-8",
                        "from":i["from"],
                        "to":str(i["id"]) + "-" + str(node_data["id"]) + "-0",
                        "threat":{  "id": i["trace data"]["common"]+"-8",
                                    "rate": get_rate(8, i["trace data"]["echo"]["q5b"])},
                        "label":"Impersonation"})

                if "q6a" in i["trace data"]["echo"]:
                    node_data["expansion"]["edges"].append({
                        "id":str(i["id"])+"-12",
                        "from":str(i["id"]) + "-" + str(node_data["id"]) + "-0",
                        "to":str(node_data["id"]) + "-0",
                        "threat":{  "id": i["trace data"]["common"]+"-12",
                                    "rate": get_rate(12, i["trace data"]["echo"]["q6a"])},
                        "label":"Interface Overload"})

                if "q6" in i["trace data"]["echo"]:
                    node_data["expansion"]["edges"].append({
                        "id":str(i["id"])+"-1",
                        "from":str(i["id"]) + "-" + str(node_data["id"]) + "-0",
                        "to":str(node_data["id"]) + "-0",
                        "threat":{  "id": i["trace data"]["common"]+"-1",
                                    "rate": get_rate(1, i["trace data"]["echo"]["q6"])},
                        "label":"Abuse of Native Code"})

    # Add outgoing nodes and edges
    if "to" in node_data:
        for i in node_data["to"]:

            if "foxtrot" in i["trace data"]:

                if "from" in node_data:
                    for j in node_data["from"]:
                        if j["id"] in i["trace data"]["foxtrot"]["from"]:
                            if "q4a" in j["trace data"]["echo"]:
                                node_data["expansion"]["edges"].append({
                                    "id":str(i["id"])+"-6",
                                    "from":j["from"],
                                    "to":i["to"],
                                    "threat":{  "id": i["trace data"]["common"]+"-6",
                                                "rate": get_rate(6, j["trace data"]["echo"]["q4a"])},
                                    "label":"Denial of Network Services"})

                            if "q4b" in j["trace data"]["echo"]:
                                node_data["expansion"]["edges"].append({
                                    "id":str(i["id"])+"-16",
                                    "from":str(j["id"]) + "-" + str(node_data["id"]) + "-0",
                                    "to":i["to"],
                                    "threat":{  "id": i["trace data"]["common"]+"-16",
                                                "rate": get_rate(16, j["trace data"]["echo"]["q4b"])},
                                    "label":"Resource Manipulation"})

                            if "q6a" in j["trace data"]["echo"]:
                                node_data["expansion"]["edges"].append({
                                    "id":str(i["id"])+"-10",
                                    "from":str(j["id"]) + "-" + str(node_data["id"]) + "-0",
                                    "to":i["to"],
                                    "threat":{  "id": i["trace data"]["common"]+"-10",
                                                "rate": get_rate(10, j["trace data"]["echo"]["q6a"])},
                                    "label":"Injecting Faults"})

                if "q7" in i["trace data"]["foxtrot"]:
                    node_data["expansion"]["edges"].append({
                        "id":str(i["id"])+"-5",
                        "from":str(node_data["id"]) + "-0",
                        "to":i["to"],
                        "threat":{  "id": i["trace data"]["common"]+"-5",
                                    "rate": get_rate(5, i["trace data"]["foxtrot"]["q7"])},
                        "label":"Denial of Local Services"})

                if "q4c" in i["trace data"]["foxtrot"]:
                    node_data["expansion"]["edges"].append({
                        "id":str(i["id"])+"-9",
                        "from":str(node_data["id"]) + "-0",
                        "to":i["to"],
                        "threat":{  "id": i["trace data"]["common"]+"-9",
                                    "rate": get_rate(9, i["trace data"]["foxtrot"]["q4c"])},
                        "label":"Indicator / Alert Manipulation"})

                if "q2" in i["trace data"]["foxtrot"]:
                    node_data["expansion"]["edges"].append({
                        "id":str(i["id"])+"-4",
                        "from":str(node_data["id"]) + "-1",
                        "to":i["to"],
                        "threat":{  "id": i["trace data"]["common"]+"-4",
                                    "rate": get_rate(4, i["trace data"]["foxtrot"]["q2"])},
                        "label":"Change of Controller Parameters"})

            if "echo" in i["trace data"]:

                if "q1" in i["trace data"]["echo"]:
                    node_data["expansion"]["edges"].append({
                        "id":str(i["id"])+"-11",
                        "from":str(node_data["id"]) + "-1",
                        "to":i["to"],
                        "threat":{  "id": i["trace data"]["common"]+"-1",
                                    "rate": get_rate(1, i["trace data"]["echo"]["q1"])},
                        "label":"Interface Device Use"})

                if "q8c" in node_data["trace data"]["echo"]:
                    node_data["expansion"]["edges"].append({
                        "id":str(i["id"])+"-2",
                        "from":str(node_data["id"]) + "-0",
                        "to":i["to"],
                        "threat":{  "id": node_data["trace data"]["common"]+"-2",
                                    "rate": get_rate(2, node_data["trace data"]["echo"]["q8c"])},
                        "label":"Abuse of Pivot Functions"})

def get_rate(threat_index, rate_factor):
    # Returns the mean time between events based on the Echo data analysis paper

    if threat_samples[threat_index] == 0:
        rate = 0
    else:
        rate = 30.42 * rate_factor * total_threat_samples / threat_samples[threat_index]

    # Adversary tier adjustment is not currently implemented, but the code is roughly
    #   rate = rate / 0.0002 * math.exp(0.041 * tier * tier + 1.1735 * tier)

    return rate

def expand_data(node_data):
    # Converts trace data echo values into ECHO question dictionaries for input into the bundle_internals function

    echo_catalog=json.load(open('trace/echo.json'))

    # Ensures every node has a "common" key, even if it means it's jsut common with itself
    if "common" not in node_data["trace data"]:
        node_data["trace data"]["common"] = str(node_data["id"])

    # Checks to see if the node trace data is a catalog entry
    if isinstance(node_data["trace data"]["echo"], str):
        if node_data["trace data"]["echo"] in echo_catalog["nodes"]:
            node_data["trace data"]["echo"] = echo_catalog["nodes"][node_data["trace data"]["echo"]].copy()
        else:
            # If it's not in the catalog (i.e. "simple"), use a standard ECHO model
            node_data["trace data"]["echo"]={"q8a":1, "q8b":1, "q8c":1}

    # Checks incoming edges for common mode and catalog entries
    if "from" in node_data:
        for i in node_data["from"]:
            if "common" not in i["trace data"]:
                i["trace data"]["common"] = str(i["id"])
            if "echo" in i["trace data"]:
                if isinstance(i["trace data"]["echo"], str):
                    if i["trace data"]["echo"] in echo_catalog["edges"]:
                        i["trace data"]["echo"] = echo_catalog["edges"][i["trace data"]["echo"]].copy()
                    else:
                        i["trace data"]["echo"]={"q4a":1,"q4b":1,"q4c":1,"q5a":1,"q6":1,"q6a":1}

    # Checks outgoing edges for common mode and catalog entries
    if "to" in node_data:
        for i in node_data["to"]:
            if "common" not in i["trace data"]:
                i["trace data"]["common"] = str(i["id"])
            if "foxtrot" in i["trace data"]:
                if i["trace data"]["foxtrot"]=="simple":
                    i["trace data"]["foxtrot"]={"q2":1,"q4c":1,"q7":1,"from":[]}
                    if "from" in node_data:
                        for j in node_data["from"]:
                            i["trace data"]["foxtrot"]["from"].append(j["id"])
            if "echo" in i["trace data"]:
                if isinstance(i["trace data"]["echo"], str):
                    if i["trace data"]["echo"] in echo_catalog["edges"]:
                        i["trace data"]["echo"] = echo_catalog["edges"][i["trace data"]["echo"]].copy()
                    else:
                        i["trace data"]["echo"]={"q1":1}
