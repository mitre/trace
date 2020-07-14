'''

NOTICE

This module was solely developed under MITRE corporation internal funding project code 10AOH630-CA

Approved for Public Release; Distribution Unlimited. Public Release Case Number 20-1780. 

(c) 2020 The MITRE Corporation. ALL RIGHTS RESERVED.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

'''

import networkx, matplotlib

def node_net(nn, results=False, involvement=False):
    # This function plots node nets
    # If there's result data in the node net and you want to visualize that, set the results parameter to true
    # If there's MTTI data in the node net and you want the results visual to be based on that instead of the MTTC data, set the involvement parameter to true

    algorithm="mttc"
    if involvement:
        algorithm="mtti"

    # This adds all the nodes to the networkx graph in order, because the order they're added is important for the networkx graph to be able to relate the display parameters to the specific nodes
    node_metadata = {}
    networkx_graph = networkx.DiGraph()
    for i in range(len(nn["nodes"])):
        networkx_graph.add_node(i, label=nn["nodes"][i]["id"])
        node_metadata[i] = {}

    # Edges are added after nodes because if an edge is added to a node that doesn't exist, the node may get added to the networkx internal node list out of order, which would cause issues plotting later
    for i in nn["edges"]:
        networkx_graph.add_edge(i["from"], i["to"])

    # Adds shapes and colors
    for i in range(len(nn["nodes"])):
        if results:
            if "results" in nn["nodes"][i]:
                if algorithm in nn["nodes"][i]["results"]:
                    node_metadata[i]["color"]=color_map((nn["nodes"][i]["results"][algorithm]-nn[algorithm]["min"])/(nn[algorithm]["max"]-nn[algorithm]["min"]))
                else:
                    node_metadata[i]["color"]=(1,1,1)

        if "foxtrot" in nn["nodes"][i]["trace data"]:
            node_metadata[i]["shape"]="D"
        else:
            if "start" in nn["nodes"][i]["trace data"]:
                node_metadata[i]["shape"]="o"
            else:
                node_metadata[i]["shape"]="s"

    # Checks to see if any nodes were missed for shapes or colors
    for i in range(len(nn["nodes"])):
        if "color" not in node_metadata[i]:
            node_metadata[i]["color"] = (1,1,1)
        if "shape" not in node_metadata[i]:
            node_metadata[i]["shape"] = "s"

    # Notes on layouts that look good:
    #   spring_layout tends to vary greatly in quality
    #   kamada_kawai_layout seems to be very stable as a spring-type
    #   shell_layout makes nodes a circle with connections inside it
    plot_data = networkx.kamada_kawai_layout(networkx_graph)

    # networkx plots need to have a separate "draw" call for each shape of node, so this automates that process
    unique_shapes=[]
    for i in node_metadata:
        if node_metadata[i]["shape"] not in unique_shapes:
            unique_shapes.append(node_metadata[i]["shape"])

    for i in unique_shapes:
        networkx.draw(networkx_graph,
                    plot_data,
                    nodelist=[x for x in node_metadata if node_metadata[x]["shape"]==i],
                    with_labels=True,
                    node_shape=i,
                    edgecolors='k',
                    node_color=[node_metadata[x]["color"] for x in node_metadata if node_metadata[x]["shape"]==i])

def trace_model(tm, results={}, involvement=False):
    # This function plots trace models
    # Results have to be passed based on the second parameter output from a find_mean function call. If you pass results data, it will visualize it. MTTC is the default data to use.
    # If there's MTTI data in the results and you want the results visual to be based on that instead of the MTTC data, set the involvement parameter to true

    algorithm="mttc"
    if involvement:
        algorithm="mtti"

    # This adds all the nodes to the networkx graph in order, because the order they're added is important for the networkx graph to be able to relate the display parameters to the specific nodes
    node_metadata = {}
    networkx_graph = networkx.DiGraph()
    for i in range(len(tm["graph"])):
        networkx_graph.add_node(i, label=tm["graph"][i]["id"])
        node_metadata[i] = {}

    # Edges are added after nodes because if an edge is added to a node that doesn't exist, the node may get added to the networkx internal node list out of order, which would cause issues plotting later
    for i in range(len(tm["graph"])):
        for j in tm["graph"][i]["edges"]:
            networkx_graph.add_edge(i, j["to"])

    # Adds colors
    if "nodes" in results:
        for i in range(len(results["nodes"])):
            if algorithm in results["nodes"][i]["results"]:
                node_metadata[i]["color"]=color_map((results["nodes"][i]["results"][algorithm]-results[algorithm]["min"])/(results[algorithm]["max"]-results[algorithm]["min"]))
            else:
                node_metadata[i]["color"]=(1,1,1)

    # Adds shapes
    for i in range(len(tm["graph"])):
        if i in tm["end"]:
            node_metadata[i]["shape"]="D"
        else:
            if "start rate" in tm["graph"][i]:
                node_metadata[i]["shape"]="o"
            else:
                node_metadata[i]["shape"]="s"

    # Checks to see if any nodes were missed for shapes or colors
    for i in range(len(tm["graph"])):
        if "color" not in node_metadata[i]:
            node_metadata[i]["color"] = (1,1,1)
        if "shape" not in node_metadata[i]:
            node_metadata[i]["shape"] = "s"

    # Notes on layouts that look good:
    #   spring_layout tends to vary greatly in quality
    #   kamada_kawai_layout seems to be very stable as a spring-type
    #   shell_layout makes nodes a circle with connections inside it
    plot_data = networkx.kamada_kawai_layout(networkx_graph)

    # networkx plots need to have a separate "draw" call for each shape of node, so this automates that process
    unique_shapes=[]
    for i in node_metadata:
        if node_metadata[i]["shape"] not in unique_shapes:
            unique_shapes.append(node_metadata[i]["shape"])

    for i in unique_shapes:
        networkx.draw(networkx_graph,
                    plot_data,
                    nodelist=[x for x in node_metadata if node_metadata[x]["shape"]==i],
                    with_labels=True,
                    node_shape=i,
                    edgecolors='k',
                    node_color=[node_metadata[x]["color"] for x in node_metadata if node_metadata[x]["shape"]==i])

def color_map(x, wash_out=.7):
    # This function takes a value from 0 to 1 and returns a color in the form of (r, g, b) simply because available colormaps didn't seem to be a good fit for this data
    # The provided logic scales from red to yellow to green in a visually appealing manner
    # A high wash_out parameter makes the colors more pastel, a low value makes them more saturated
    color=[1,1,wash_out]
    if x<0.5:
        color[1]=wash_out+(1-wash_out)*2*x
    else:
        color[0]=1-(1-wash_out)*2*(x-.5)
    return color
