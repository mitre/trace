'''

NOTICE

This module was solely developed under MITRE corporation internal funding project code 10AOH630-CA

Approved for Public Release; Distribution Unlimited. Public Release Case Number 20-1780. 

(c) 2020 The MITRE Corporation. ALL RIGHTS RESERVED.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

'''

from . import echo
import copy

def bundle_edges(nn):
    # This copies edge dictionaries inside "to" and "from" lists inside the associated node dictionaries for convenient reference in the expansion step
    for i in nn["edges"]:
        if "from" not in nn["nodes"][i["to"]]:
            nn["nodes"][i["to"]]["from"]=[]
        nn["nodes"][i["to"]]["from"].append(i.copy())
        if "to" not in nn["nodes"][i["from"]]:
            nn["nodes"][i["from"]]["to"]=[]
        nn["nodes"][i["from"]]["to"].append(i.copy())

def add_node(tm, j, nn_node):
    # This consistently copies relevant node data from a node net to a TRACE node
    tm["graph"].append(j)
    tm["graph"][-1]["nn node"]=nn_node
    tm["graph"][-1]["edges"]=[]
    if "trace data" in j:
        if "end" in j["trace data"]:
            tm["end"].append(len(tm["graph"]) - 1)
    if "trace data" in j:
        if "start" in j["trace data"]:
            tm["graph"][-1]["start rate"] = j["trace data"]["start"]
    for i in ["trace data", "from", "to", "expansion"]:
        if i in tm["graph"][-1]:
            tm["graph"][-1].pop(i)

def stitch_tm(nn):
    # This takes a node net with expansions and stitches the expansions together as a single trace model
    tm = {  "age":0.0,
            "end":[],
            "threats":{},
            "graph":[]}

    # This is used to track where in the TRACE model graph list a specific node net id can be found
    nn_to_tm_translator = {}

    # This adds all the nodes in the node net nodes list to the TRACE model graph
    for i in nn["nodes"]:
        if i["id"] not in nn_to_tm_translator:
            nn_to_tm_translator[i["id"]]=len(tm["graph"])
            add_node(tm, i.copy(), i["id"])
        else:
            print ("Warning, duplicate major node id found: " + str(i["id"]))

        # This adds any internal expansion nodes as well
        if "expansion" in i:
            # Note on arbitrary broken symmetry for edge stitching between nodes: For edges in the expansion that list a non-internal "from" node (nodes not in the "expansion" nodes list), those "from" references will be replaced with a self-reference. The outgoing edge at the "from" node will then be able to connect to that reference.
            for j in i["expansion"]["nodes"]:
                if j["id"] not in nn_to_tm_translator:
                    nn_to_tm_translator[j["id"]]=len(tm["graph"])
                    add_node(tm, j.copy(), i["id"])
                else:
                    print ("Warning, duplicate internal node id found: " + str(j["id"]))

    # This adds edges to the TRACE model. Note that all the edges have already been bundled into the node data at this point, so no need to traverse the edges list.
    for i in nn["nodes"]:
        if "expansion" in i:
            for j in i["expansion"]["edges"]:
                if j["from"] not in nn_to_tm_translator:
                    print ("Warning, unknown node id found: " + str(j["from"]))
                else:
                    if j["to"] not in nn_to_tm_translator:
                        print ("Warning, unknown node id found: " + str(j["to"]))
                    else:
                        if j["from"] not in [x["id"] for x in i["expansion"]["nodes"]]:
                            tm["graph"][nn_to_tm_translator[i["id"]]]["edges"].append({"to":nn_to_tm_translator[j["to"]],"threat":j["threat"]["id"]})
                            tm["threats"][j["threat"]["id"]]=j["threat"]
                        else:
                            tm["graph"][nn_to_tm_translator[j["from"]]]["edges"].append({"to":nn_to_tm_translator[j["to"]],"threat":j["threat"]["id"]})
                            tm["threats"][j["threat"]["id"]]=j["threat"]
        else:
            if "to" in i:
                for j in i["to"]:
                    if j["to"] not in nn_to_tm_translator:
                        print ("Warning, unknown node id found: " + str(j["to"]))
                    else:
                        tm["graph"][nn_to_tm_translator[j["from"]]]["edges"].append({"to":nn_to_tm_translator[j["to"]],"threat":j["id"]})
                        tm["threats"][j["id"]]={"rate":0}

    return tm

def nn_to_tm(input_nn):
    # This function calls the steps to turn a node net into a trace model

    nn=copy.deepcopy(input_nn)

    bundle_edges(nn)

    for i in nn["nodes"]:
        if "echo" in i["trace data"]:
            echo.expansion(i)

    tm = stitch_tm(nn)

    return tm

def tm_results_to_nn(tm, results, input_nn):
    # This traverses a TRACE model and copies appropriate result data back to associated nodes in a given node net. Note that if the provided node net isn't the one used to create the TRACE model, the output might not make sense or this function could error.

    nn = copy.deepcopy(input_nn)
    nn["histories"]=results["histories"]
    nn["mttc"]=results["mttc"]
    if "mtti" in results:
        nn["mtti"]=results["mtti"]

    for x in ["mttc", "mtti"]:
        for i in range(len(results["nodes"])):
            if x in results["nodes"][i]["results"]:
                for j in nn["nodes"]:
                    if "results" not in j:
                        j["results"]={}
                    if j["id"]==tm["graph"][i]["nn node"]:
                        if x not in j["results"]:
                            j["results"][x]=results["nodes"][i]["results"][x]
                            if x+" samples" in results["nodes"][i]["results"]:
                                j["results"][x + " samples"]=results["nodes"][i]["results"][x + " samples"]
                        else:
                            if j["results"][x]>results["nodes"][i]["results"][x]:
                                j["results"][x]=results["nodes"][i]["results"][x]
                                if x + " samples" in results["nodes"][i]["results"]:
                                    j["results"][x + " samples"]=results["nodes"][i]["results"][x + " samples"]
    return nn
