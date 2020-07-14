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

def trace_model_demo(population=20, tm=-1):
    # This demo generates and analyzes a random TRACE model
    if tm==-1:
        # If a TRACE model is not provided, generate one. This function
        #   generates a TRACE model directly based on a number of nodes, a
        #   fraction of connections relative to a fully-connected graph, and a
        #   number of unique threat concepts that are randomly distributed
        #   across those connections. Note that all graphs in TRACE are directed
        #   graphs with cycles.
        print ("Generating random TRACE model")
        tm = trace.generate.trace_model.random(population, 1.5/population, int(population/2)+1)

    # Run analyses

    # The find_time function finds the time that a trace model has any completed
    #   path with a given probability by aging a model to different times
    # hunt_depth is an optional parameter that is set higher here to give a more
    #   interesting visual and higher accuracy results for the demo, in practice
    #   it's not generally necessary to have high accuracy for most uses of this
    medianTTC, median_results = trace.montecarlo.find_time(tm, .5, verbose=True, hunt_depth=100)

    # The find_mean function ages a model to specific set intervals over and
    #   over to characterize the overall distribution
    # node_details is an optional parameter to capture detailed information on
    #   a per-node basis, which has a mild impact on computation time
    # cc is an optional parameter which lets the user specify convergence
    #   criteria in terms of (number of consecutive samples that must meet
    #   criteria, max probability delta across those samples, max days % change
    #   across those samples), however the probability delta isn't used for
    #   the find_mean function, only for the find_time function
    mean, mean_results = trace.montecarlo.find_mean(tm, node_details=True, verbose=True, cc=(100,.01,.01))

    # To turn find_mean into an MTTI analysis, just add the optional involvement
    #   parameter and set it to true. This makes the function call the MTTI
    #   algorithm instead of the MTTC algorithm. The MTTC algorithm uses a
    #   simple spanning tree, but MTTI does an exhaustive recursive backtracking
    #   through the entire graph every time step, which is much more work
    mtti, mtti_results = trace.montecarlo.find_mean(tm, node_details=True, involvement=True, verbose=True, cc=(100,.01,.01), timeframe=mean_results["timeframe"])

    # Output some visuals
    # The trace.plot module provides a few visuals using standard packages
    print ("\nPlotting data")
    figure = matplotlib.pyplot.figure()

    plot=figure.add_subplot(231)
    plot.set_title('Generated TRACE Graph')
    # The trace_model function plots a basic trace model with or without results
    trace.plot.trace_model(tm)

    plot=figure.add_subplot(234)
    plot.set_title('Median TTC: ' + str(round(medianTTC, 2)) + '\n\n\nMedian TTC Convergence\n' + str(median_results["histories"]) + " Steps")
    plot.set_xlabel("Trial")

    # The find_time and find_mean functions return information about convergence
    #   which is plotted here
    plot.plot([x for x in range(len(median_results["t"]))], median_results["t"], "b")
    plot.set_ylabel("Days to compromise (blue)")

    plot = plot.twinx()
    plot.plot([x for x in range(len(median_results["p"]))], median_results["p"], "r")
    plot.set_ylabel('Probability (red)')

    plot = figure.add_subplot(232)
    plot.set_title('MTTC Result')

    # To make the trace.plot.trace_model function plot a gradient color scale
    #   for MTTC analysis results, also pass the results returned by find_mean
    trace.plot.trace_model(tm, mean_results)

    plot=figure.add_subplot(235)
    plot.set_title('MTTC: ' + str(round(mean, 2)) + '\n\n\nMean TTC Convergence\n' + str(mean_results["histories"] * mean_results["resolution"]) + " Steps")
    plot.set_xlabel("Trial")
    plot.plot([x for x in range(len(mean_results["t"]))], mean_results["t"], "b")
    plot.plot([x for x in range(len(mean_results["mu"]))], mean_results["mu"], "r")
    plot.set_ylabel('Trial compromise time (blue)\nand running average (red)')

    plot = figure.add_subplot(233)
    plot.set_title('MTTI Result')
    # To make trace.plot.trace_model plot the MTTI, use the involvement option
    trace.plot.trace_model(tm, mtti_results, involvement=True)

    plot=figure.add_subplot(236)
    plot.set_title('MTTC from MTTI: ' + str(round(mtti, 2)) + '\n(Should match)\n\nMean TTI Convergence\n' + str(mtti_results["histories"] * mtti_results["resolution"]) + " Steps")
    plot.set_xlabel("Trial")
    plot.plot([x for x in range(len(mtti_results["t"]))], mtti_results["t"], "b")
    plot.plot([x for x in range(len(mtti_results["mu"]))], mtti_results["mu"], "r")
    plot.set_ylabel('Trial overall compromise time (blue)\nand running average (red)')

    matplotlib.pyplot.get_current_fig_manager().window.showMaximized()
    matplotlib.pyplot.tight_layout()
    matplotlib.pyplot.show()

if __name__=="__main__":
    trace_model_demo()
