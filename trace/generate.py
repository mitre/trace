'''

NOTICE

This module was solely developed under MITRE corporation internal funding project code 10AOH630-CA

Approved for Public Release; Distribution Unlimited. Public Release Case Number 20-1780. 

(c) 2020 The MITRE Corporation. ALL RIGHTS RESERVED.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

'''

import random, json

class node_net:

    def random(n, c):
        # This function returns a node net with random Echo nodes
        #   n (int) is the number of nodes
        #   c (float) is the average connectivity ratio, where each node will have an average number of outgoing edges of n*c, thus 1 is a fully connected graph and 0 is a fully disjoint graph

        nn = { "nodes" : [], "edges" : [] }
        echo_catalog=json.load(open('trace/echo.json'))
        echo_catalog["nodes"]=list(echo_catalog["nodes"].keys())
        echo_catalog["edges"]=list(echo_catalog["edges"].keys())[:5]

        # For now, arbitrarily 10% of nodes will be start nodes and 10% will be end foxtrot nodes, with a minimum of 1 each
        separates = int(n / 10)
        if separates < 1:
            separates = 1

        # Add start nodes
        for i in range(separates):
            nn["nodes"].append({"id":i,"trace data":{"start":0}})

        # Add echo nodes
        for i in range(separates, n-separates):
            nn["nodes"].append({"id":i,"trace data":{}})
            nn["nodes"][-1]["trace data"]["echo"]=random.choice(echo_catalog["nodes"])

        # Add foxtrot nodes
        for i in range(n-separates,n):
            nn["nodes"].append({"id":i,"trace data":{"foxtrot":"simple","end":True}})

        # Connect at least one path through all the echo nodes
        for i in range(separates, n-separates-1):
            nn["edges"].append({"id":len(nn["edges"]),"from":i,"to":i+1,"trace data":{}})
            nn["edges"][-1]["trace data"]["echo"]=random.choice(echo_catalog["edges"])

        # Connect at least the last echo node to the last foxtrot node
        nn["edges"].append({"id":len(nn["edges"]),"from":n-separates-1,"to":n-1,"trace data":{"foxtrot":"simple"}})

        # Connect start nodes to random echo nodes
        for i in range(separates):
            nn["edges"].append({"id":len(nn["edges"]),"from":i,"to":random.randint(separates, n-separates-1),"trace data":{}})
            nn["edges"][-1]["trace data"]["echo"]=random.choice(echo_catalog["edges"])

        # Connect random echo nodes to all foxtrot nodes
        for i in range(n-separates, n):
            nn["edges"].append({"id":len(nn["edges"]),"from":random.randint(separates, n-separates-1),"to":i,"trace data":{}})
            nn["edges"][-1]["trace data"]["foxtrot"]="simple"

        # Connect random echo nodes to eachother until connectivity is satisfied
        for i in range(len(nn["edges"]), int(c*n*n)+1):
            from_node = int(random.random()*(n-separates*2))+separates
            to_node = int(random.random()*(n-separates*2-1))+separates
            if to_node>=from_node:
                to_node=to_node+1
            nn["edges"].append({"id":len(nn["edges"]),"from":from_node,"to":to_node,"trace data":{}})
            nn["edges"][-1]["trace data"]["echo"]=random.choice(echo_catalog["edges"])

        return nn

class trace_model:

    def random(n, c, t, allow_duplicate_edges=False):
        # This function returns a trace model
        #   n (int) is the number of nodes
        #   c (float) is the average connectivity ratio, where each node will have an average number of outgoing edges of n*c, thus 1 is a fully connected graph and 0 is a fully disjoint graph
        #   t (int) is the number of unique threat events
        #   allow_duplicate_edges toggles whether graphs are generated with duplicate edges

        # Node 0 is identified as the only starting point, and node n is the end point

        # Initialize the trace model dictionary
        tm = {  "age":0.0,
                "end":[n-1],
                "threats":{},
                "graph":[{"id":i,"edges":[]} for i in range(n)]}

        # A start value of 0 means it has an initiating threat event on average every 0 days (so it's compromised from the beginning)
        tm["graph"][0]["start rate"]=0

        # Add a chain of connectivity from start to end to obviate the need to do disjoint checking
        for i in range(n):
            if i < n - 1:
                tm["graph"][i]["edges"].append({"to":(i+1)})

        # Randomly connect nodes until desired connectivity is satisfied
        if allow_duplicate_edges:
            for i in range(int(round(n*n*c-(n-1),0))):
                # This does a quick "pick two without replacement," and also note that using random.randrange or random.randint is much slower than this use of random.random
                from_node = int(random.random()*n)
                to_node = int(random.random()*(n-1))
                if to_node>=from_node:
                    to_node=to_node+1
                tm["graph"][from_node]["edges"].append({"to":to_node})
        else:
            for i in range(int(round(n*n*c-(n-1),0))):
                # This does a quick "pick two without replacement," and also note that using random.randrange or random.randint is much slower than this use of random.random
                from_node = random.choice([x for x in range(len(tm["graph"])) if len(tm["graph"][x]["edges"])<n])
                allowable_to = [x for x in range(len(tm["graph"])) if x not in [y["to"] for y in tm["graph"][from_node]["edges"]]]
                to_node = random.choice(allowable_to)
                tm["graph"][from_node]["edges"].append({"to":to_node})

        # Add threats, using integers as keys simply for convenience
        for i in range(t):
            # 30 is arbitrary, but represents the mean number of days for the distribution. This could be replaced by values within a range or an input value. For this example code, 30 is used.
            tm["threats"][i]={"rate":30}

        # Assign threats randomly to edges
        for i in tm["graph"]:
            for j in i["edges"]:
                j["threat"]=int(random.random()*t)

        return tm
