'''

NOTICE

This module was solely developed under MITRE corporation internal funding project code 10AOH630-CA

Approved for Public Release; Distribution Unlimited. Public Release Case Number 20-1780. 

(c) 2020 The MITRE Corporation. ALL RIGHTS RESERVED.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

'''

import trace
import matplotlib.pyplot

def nn_test(nn=-1):
    # This demo generates and analyzes a random node net model
    if nn==-1:
        # This generates a random node net with 5 nodes and which has 30% of
        #   the connections of a fully connected graph
        nn=trace.generate.node_net.random(5,.3)

        '''
        A simple example node net model is provided here to give perspective on
            how node net data is structured. It's a dictionary with two lists,
            "nodes" and "edges". Note that all graphs in TRACE are directed
            graphs with cycles.

        nn={"nodes":[{"id":0,"trace data":{"start":0}},
                     {"id":1,"trace data":{"echo":"Windows_XP_Desktop"}},
                     {"id":2,"trace data":{"foxtrot":"simple", "end":True}}],
            "edges":[{"id":0,"from":0,"to":1,"trace data":{"echo":"IP"}},
                     {"id":1,"from":1,"to":2,"trace data":{"foxtrot":"simple"}}]}

        The "nodes" list contains dictionaries that define the nodes:
            "id" : (int) or (str)
                A unique identifier used by the "edges" to link nodes together
            "trace data" : {}
                Specifies model data, should contain one of:
                    "start" : (float)
                        This tells the transform function this should be a node
                        where attacks start after N days, 0 for immediate.
                    "echo" : "simple", "catalog entry", {custom data}
                        This tells the transform function this should be a cyber
                        component, either using a standard model, a specific
                        model from the echo.json catalog, or some customer model
                        matching the echo.json dictionary format.
                    "foxtrot" : "simple", {custom data}
                        This tells the transform function this should be a
                        functional node, part of representing how the system
                        works. In this implementation, these are essentially
                        all "or" gates.
                Typically, at least one "foxtrot" node should contain an "end"
                    key with the boolean value True to tell the transform tool
                    where to end analyses. If an end is not specified, one will
                    be selected automatically.

        The "edges" list contains dictionaries that define the links between
            nodes:
            "id" : (int) or (str)
                Each edge has a unique identifier.
            "trace data" : {}
                Specifies model data, should contain one of:
                    "echo", "foxtrot" : "simple", "catalog entry", {custom data}
                        This specifies the type of link, either a cyber
                        interface ("echo") or a functional relationship
                        ("foxtrot").
        '''


    # Node nets need to be transformed into TRACE graphs to get results.
    #   Functions in the trace.run module perform this transformation
    #   transparently on input data
    tm=trace.transform.nn_to_tm(nn)

    # MTTI results also contain MTTC result data, because the MTTI algorithm can
    #   provide both analysis results
    mtti, mtti_results = trace.montecarlo.find_mean(tm, node_details=True, involvement=True, verbose=True, cc=(100,.01,.01))

    # To be able to visualize the TRACE results in the original node net, the
    #   TRACE model result data needs to be related back to the node net
    nn = trace.transform.tm_results_to_nn(tm, mtti_results, nn)

    figure = matplotlib.pyplot.figure()

    plot=figure.add_subplot(231)
    plot.set_title('Generated Node Net')
    # A specific function is provided to create visuals of node nets, primarily
    #   because the TRACE model graphs are not structured as adjacency lists
    trace.plot.node_net(nn)

    plot=figure.add_subplot(232)
    plot.set_title('MTTC Result')
    trace.plot.node_net(nn, results=True)

    plot=figure.add_subplot(233)
    plot.set_title('MTTI Result')
    trace.plot.node_net(nn, results=True, involvement=True)

    plot=figure.add_subplot(234)
    plot.set_title('Expanded Trace Model')
    trace.plot.trace_model(tm)

    plot = figure.add_subplot(235)
    plot.set_title('Trace Model Result')
    trace.plot.trace_model(tm, mtti_results, involvement=True)

    plot=figure.add_subplot(236)
    plot.set_title('MTTC: ' + str(round(mtti, 2)) + '\n\n\nSimulation Convergence\n' + str(mtti_results["histories"] * mtti_results["resolution"]) + " Steps")
    plot.set_xlabel("Trial")
    plot.plot([x for x in range(len(mtti_results["t"]))], mtti_results["t"], "b")
    plot.plot([x for x in range(len(mtti_results["mu"]))], mtti_results["mu"], "r")
    plot.set_ylabel('Trial overall compromise time (blue)\nand running average (red)')

    matplotlib.pyplot.get_current_fig_manager().window.showMaximized()
    matplotlib.pyplot.tight_layout()
    matplotlib.pyplot.show()

if __name__=="__main__":
    nn_test()
