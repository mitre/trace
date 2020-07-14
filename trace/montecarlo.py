'''

NOTICE

This module was solely developed under MITRE corporation internal funding project code 10AOH630-CA

Approved for Public Release; Distribution Unlimited. Public Release Case Number 20-1780. 

(c) 2020 The MITRE Corporation. ALL RIGHTS RESERVED.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

'''

import random, math, numpy

def age_model(tm, dt):
    # This function iterates through threats and starting points in a given TRACE model and "rolls the dice" on them for given amount of time passing
    for i, j in tm["threats"].items():
        if "on" not in j:
            if j["rate"]==0:
                j["on"]=True
            else:
                if random.random() < 1-math.exp(-dt/j["rate"]):
                    j["on"]=True
    for i in tm["graph"]:
        if "start rate" in i:
            if "started" not in i:
                if i["start rate"]==0:
                    i["started"]=True
                else:
                    if random.random() < 1-math.exp(-dt/i["start rate"]):
                        i["started"]=True
    tm["age"]=tm["age"]+dt

def check_model(tm, stop_at_hit=True, involvement=False):
    # This function performs a path check of the model to find MTTC and MTTI
    
    # This has been implemented using a dictionary here simply to improve readiblity. In practice, this function is typically implemented in compiled code using a variety of fixed-width integer and floating point arrays
    
    # The concept of operation of this algorithm is to first use a spanning tree to find all nodes which are connected to an entry point through a realized threat concept (where the Monte Carlo "dice roll" has turned that vulnerability on). This spanning tree then represents all nodes that can be reached with some set of available vulnerabilities for a given model age. The spanning tree is stored in the "stack" list as individual tm["graph"] list indices

    # After the spanning tree is completed, the reached nodes are traced backwards from all "end" nodes to determine which nodes are involved in an end-to-end path. Since all nodes that are reached must be in a path from some entry point, all nodes which connect to an end node or to any node that connects to an end node ad infinitum must consequently be in a path from an entry point to an end node.

    # A key concept here is that each node gets a "hit" key when it is reached by the spanning tree that contains the value of the model age the first time it was reached. If that node is then shown to be part of an end-to-end path, it gets an "involved" key containing the model age when that path was confirmed.

    
    # This loops through the graph and initializes a stack that contains all nodes that are "started" based on the Monte Carlo or have been reached in a previous history.
    stack=[]
    for i in range(len(tm["graph"])):
        # While not shown in the provided examples, the "coincidence" key allows for use of "AND"-like logic, where the "coincidence" value represents the number of incoming edges that must be activated before the node is considered "reached." This reinitializes that count for this spanning tree run.
        if "coincidence" in tm["graph"][i]:
            tm["graph"][i]["coincidence hits"]=tm["graph"][i]["coincidence"]

        # This adds nodes to the stack that have been previously reached or are started 
        if "hit" in tm["graph"][i] or "involved" in tm["graph"][i] or "started" in tm["graph"][i]:
            stack.append(i)
            # If the node is in the stack, it is by definition "hit"
            if "hit" not in tm["graph"][i]:
                tm["graph"][i]["hit"] = tm["age"]
                # If it's an end node and it's in the stack, it is by definition "involved"
                if i in tm["end"] and "involved" not in tm["graph"][i]:
                    tm["graph"][i]["involved"] = tm["age"]
    
    # This will loop through all items in the stack, even if items are added while in the loop
    for i in stack:
        # This checks every outgoing edge on each node to see if the target should be added to the spanning tree stack
        for j in tm["graph"][i]["edges"]:
            # If the threat is active, we might be able to add the target to the stack
            if "on" in tm["threats"][j["threat"]]:
                # If it's not in the stack, add it
                if j["to"] not in stack:
                    # If it's a coincidence node, subtract one from the coincidence hits before we check to see if we can add it to the stack
                    if "coincidence" in tm["graph"][j["to"]]:
                        tm["graph"][j["to"]]["coincidence hits"] = tm["graph"][j["to"]]["coincidence hits"] - 1

                    # If it's not a coincidence node, or if the coincidence hits is down to zero, add it to the stack
                    if "coincidence hits" not in tm["graph"][i] or tm["graph"][i]["coincidence hits"] <= 0:
                        stack.append(j["to"])
                        # If it hasn't been hit before, it got hit at this model age
                        if "hit" not in tm["graph"][j["to"]]:
                            tm["graph"][j["to"]]["hit"] = tm["age"]
                        # If this is a target node, then it's by definition "involved" and the overall model is "hit"
                        if j["to"] in tm["end"]:
                            if "involved" not in tm["graph"][j["to"]]:
                                tm["graph"][j["to"]]["involved"] = tm["age"]
                            if "hit" not in tm:
                                tm["hit"]=True
                            # Leave now if we're supposed to
                            if stop_at_hit:
                                break

                # If the target is "involved," so is this node. This just makes checking for this a little faster later.
                if "involved" in tm["graph"][j["to"]] and "involved" not in tm["graph"][i]:
                    tm["graph"][i]["involved"] = tm["age"]

        # Leave if we're supposed to after getting a hit
        if stop_at_hit and "hit" in tm:
            break

    # This goes back through the stack to check for involvement in end-to-end paths
    if involvement and not (stop_at_hit and "hit" in tm):
        # Worst case we need to check the stack len(stack) number of times. This might go faster if we store the stack between model checks, since populating the stack using the spanning tree should naturally sort nodes into an order that's fast to do this in reverse on, but that isn't done here simply for simplicity.
        for k in stack:
            no_change = True
            # If you go backwards through the stack, you can take advantage of the fact that nodes in a valid path should be added sequentially
            for ix in range(len(stack)):
                i = len(stack) - ix - 1
                # If the node isn't in a path, see if it connects to someone who is
                if "involved" not in tm["graph"][stack[ix]]:
                    for j in tm["graph"][stack[ix]]["edges"]:
                        # If any of the valid edges go to a node that's in a path, this node is in a path
                        if "involved" in tm["graph"][j["to"]] and "on" in tm["threats"][j["threat"]]:
                            no_change = False
                            tm["graph"][stack[ix]]["involved"] = tm["age"]
                            break
            # If no new nodes were modified after checking the whole stack, we don't need to check it anymore
            if no_change:
                break

    if "hit" in tm:
        return True
    else:
        return False

def check_hits(tm):
    # This function is not used, but included as an alternative to the check_model function for MTTC analysis, and can be used to validate those results if desired.
     
    # This function uses a simple spanning tree to check for any connectivity between any "start" nodes and any "end" nodes, which would signify that the model has a "hit". It isn't technically a completely different approach, but the algorithm is so simple that it is much easier to check by hand that it should be correct.

    # Notably, cursory testing suggests this is ~8x faster than configuring the model to use the networkx built in has_path method, which also would only work from one starting point to one end
    
    stack=[]
    for i in range(len(tm["graph"])):
        if "started" in tm["graph"][i]:
            stack.append(i)
            if "hit" not in tm["graph"][i]:
                tm["graph"][i]["hit"] = tm["age"]
    for i in stack:
        for j in tm["graph"][i]["edges"]:
            if j["to"] not in stack:
                if "on" in tm["threats"][j["threat"]]:
                    stack.append(j["to"])
                    if "hit" not in tm["graph"][j["to"]]:
                        tm["graph"][j["to"]]["hit"] = tm["age"]
        if i in tm["end"]:
            tm["hit"] = True
    if "hit" in tm:
        return True
    else:
        return False

def check_involvement(tm):
    # This function is not used, but is included as an alternative to the check_model function for MTTI analysis, and can be used to validate those results if desired.
     
    # This is an alternative algorithm that provides the mean time to involvement measure

    # This algorith uses a stack to track the path taken through the graph
    # When a dead end is found, it backtracks up the stack
    # It uses the list index of the outgoing edges in the stack to track
    #   paths it has gone down before
    # If it reaches a node in the "end" list, it sets the "hit" time for
    #   every node in the stack to the current model age, if not already
    #   set by an earlier hit
    # Each index of the stack contains a node and the edge index used to
    #   leave that node, so that when the algorithm backtracks it knows
    #   where it's been before

    # This algorithm uses a boolean called "backtrack" to keep track of
    #   whether it needs to backtrack. If there are no valid outgoing edges
    #   (edges whose threats are "on" and whose destination isn't in the
    #   stack), then backtrack is true and the last node is popped from/
    #   the stack.

    # Go through all the nodes in the graph
    for i in range(len(tm["graph"])):

        # If a node has been designated as "started" by the age_model function, then start an attack path recursion from it
        if "started" in tm["graph"][i]:

            # Start a fresh stack using the started node
            stack={"nodes":[tm["graph"][i]["id"]],"edges":[]}
            if "hit" not in tm["graph"][stack["nodes"][-1]]:
                tm["graph"][stack["nodes"][-1]]["hit"]=tm["age"]

            # Use a safety loop that allows for lots of backtracking steps, the upper end of the loop is arbitrary, but may be exceeded in very large models
            for safety in range(1000000000):
                # Assumed behavior is to backtrack unless a valid destination node is found
                backtrack = True

                # Iterate through all the outgoing edges from the last node in the stack
                for j in range(len(tm["graph"][stack["nodes"][-1]]["edges"])):
                    # Check to see if you entered this for loop after a backtrack, in which case the last outgoing edge attempted will still be in the edge stack, making the edge stack as long as the node stack
                    if len(stack["edges"])==len(stack["nodes"]):
                        # If the edge the for loop is looking at is earlier in the outgoing edge list than the one currently in the stack, then...
                        if j<=stack["edges"][-1]:
                            # If the one currently in the stack is the last one in the outgoing edge list (or higher as a bug check), then leave the for loop, which will result in a backtrack
                            if stack["edges"][-1] >= len(tm["graph"][stack["nodes"][-1]]["edges"])-1:
                                break
                            else:
                                # Otherwise, set the for loop to the next unchecked outgoing edge
                                stack["edges"][-1]=stack["edges"][-1]+1
                                j = stack["edges"][-1]
                    # If the threat for the outgoing edge being checked is "on", then...
                    if "on" in tm["threats"][tm["graph"][stack["nodes"][-1]]["edges"][j]["threat"]]:
                        # If the destination node is not in the stack, then...
                        if tm["graph"][stack["nodes"][-1]]["edges"][j]["to"] not in stack["nodes"]:
                            # If there's no outgoing edge associated with the last node in the stack, add this outgoing edge to the edge stack
                            if len(stack["edges"])<len(stack["nodes"]):
                                stack["edges"].append(j)
                            # Add the destination node to the node stack
                            stack["nodes"].append(tm["graph"][stack["nodes"][-1]]["edges"][j]["to"])
                            if "hit" not in tm["graph"][stack["nodes"][-1]]:
                                tm["graph"][stack["nodes"][-1]]["hit"]=tm["age"]
                            # Don't backtrack, but do get out of this loop so we can restart the outgoing edge checking process from the next node
                            backtrack = False
                            break
                # Now that you're out of the outgoing edge checking for loop, see if we've just stepped into a node in the "end" list
                if not backtrack:
                    if stack["nodes"][-1] in tm["end"]:
                        # If we have, we can backtrack after we set all the nodes in the stack to have a hit time of now (if they don't already have a hit time)
                        backtrack = True
                        tm["hit"] = True
                        for j in stack["nodes"]:
                            if "involved" not in tm["graph"][j]:
                                tm["graph"][j]["involved"]=tm["age"]
                # If we're backtracking, pop the last node and possibly the last edge from the stack, and if we've run out of stack, exit the safety for loop and go on to find the next starting point (if any)
                if backtrack:
                    stack["nodes"].pop()
                    if len(stack["nodes"])==0:
                        break
                    if len(stack["edges"])>len(stack["nodes"]):
                        stack["edges"].pop()
    # This lets the function act like a simple checker if you don't want to dig into the "hit" values yourself
    if "hit" in tm:
        return True
    else:
        return False

def run_history(tm, t, dt, stop_at_hit=False, involvement=False):
    # Ages tm from the current state by time t in steps of dt
    # The stop_at_hit parameter will stop the loop if any full path is completed
    # The involvement parameter toggles between check hits (just MTTC) and check involvement (MTTI and MTTC)
    hits=False
    age_model(tm, 0)
    for i in range(int(t/dt)+2):
        hits = check_model(tm, stop_at_hit=stop_at_hit, involvement=involvement)
        if hits and stop_at_hit:
            break
        age_model(tm, dt)

def reset_history(tm):
    # Reset threat states
    if "hit" in tm:
        tm.pop("hit")
    tm["age"]=0.0
    for i in tm["graph"]:
        if "hit" in i:
            i.pop("hit")
        if "involved" in i:
            i.pop("involved")
    for i, j in tm["threats"].items():
        if "on" in j:
            j.pop("on")

def find_time(tm, p, cc=(20,.05,.05), verbose=False, hunt_depth=5):
    # Returns the time when model tm has full paths with probability p
    # "cc" is the convergence criteria in terms of (trials, probability, time), where the results is considered converged when the past cc[0] trials are within the range of cc[1] and cc[2], this setting is a fairly quick low-quality result, something like (200, .001, .001) is pretty high quality
    # The verbose parameter gives lots of detailed output when True
    # The hunt_depth parameter gives the starting number of runs to do per bundle when hunting for a starting value. 5 is a fairly minimal "enough," turning it up might just waste time

    if verbose:
        print ("\nFinding time for probability of " + str(round(p,4)))
    dt = 10

    if verbose:
        print ("Doubling time until getting regular hits")

    trials={"p":[0],"t":[0],"histories":0}
    # Run a loop aging a model a few times at a given age, then doubling that age until the result is regular hits, giving a rough timeframe to start a more detailed hunting algorithm. 100 doublings is enough to cause the code to crash if it doesn't find any valid paths, which is likely a sub-optimal way to check for that issue.
    for i in range(100):
        hits=0
        for j in range(hunt_depth):
            run_history(tm, dt, dt, stop_at_hit=True)
            if "hit" in tm:
                hits=hits+1
            reset_history(tm)
        trials["p"].append(hits/hunt_depth)
        trials["t"].append(dt)
        trials["histories"]=trials["histories"]+hunt_depth
        if hits > hunt_depth*p:
            break
        dt=dt+dt

    """
	Notes on math:
        Casual experimentation for graphs with no coincidence above 1 indicates that cdfs for connectivity over time appear to follow a particular general form. Unfortunately, that form is not trivially inverted without using some unusual functions (Lambert W function, the "product log").

        Consequently, this hunt function treats the curve as a simple exponential curve for the purpose of predicting the next guess. Nevertheless, I felt it was important to explain why that is wrong.

        Compromise time cdfs can be observed to be well-described by a compound exponential distribution of the form:

            cdf[t] = 1-exp(-t*(a*exp(-b*t)))

        Where a and b are some constants describing the shape of the curve.

        We can find coefficients a and b given some points, maybe t_0=0, cdf_0=0; t_n=x1, cdf_n=y1; t_f=x2, cdf_n=y2

        Rearranging the general form:

            a*exp(-b*t) = -t / (ln(1-cdf[t])) = k

        Solving for a:

            a=k*exp(-b*t)

        Inserting knowns, substituting into the two above functions, and solving for a and b:

            b=ln(k1/k2)/(x2-x1)
                =ln((-x1/ln(1-y1))/(-x2/ln(1-y2)))/(x2-x1)
            a=k1*exp(x1*b)
                =(-x1/ln(1-y1))*exp(x1*b)

        From here it is observed that all the sample points must be non-zero to avoid 0/0, thus we need non-zero x1 and x2 values.

        While also not used in this module, the expectation value for any curve can now be readily found via Fubini's thereom:

            E[x]={integral from 0 to inf of (1-F(x))dx} - {integral from -inf to 0 of F(x)dx}

        Given cdf =0 for t<=0, we can ignore the second integral, leaving:

            E[x]={integral from 0 to inf of (exp(-t*(a*exp(-b*t))))dx}

        I cannot find a closed form solution for this, but it can be trivially numerically approximated given a and b.

        Thus, collecting two data points, nominally points with values that are not close to zero or one, can potentially allow for rapid estimation of expectation value for any graph.
    """

    # This provides for the case where a start and end node are directly connected
    if dt==0:
        return 0, trials

    if verbose:
        print ("Hunting for t")

    # This value is somewhat arbitrarily selected to prevent the automated hunting from
    #   jumping "too much" in a single guess
    slow_hunt_growth = 1.2

    # This loop hunts to find a time dt where a series of monte carlo runs consistently results in a hit rate of p
    for i in range(1000):
        if hits == 0:
            # This covers the special case where a previous run loop didn't get any hits, which would cause an error in the math downstream otherwise
            dt = dt*1.2
        else:
            if hits == hunt_depth:
                # This covers the case where 100% of the trials in the last bundle had completed paths, which is a somewhat non-useful result so we need to dial time down a notch
                dt = dt * (1 - cc[2])
            else:
                # This covers the case where we have a "good" data point to try and predict from. A few different methods are shown here with notes.

                # Using numpy polyfit is fast and stable, but if it doesn't have a bias for 0,0 being on the curve it sometimes gets stuck just a little bit off and never converges
                m, b = numpy.polyfit([0] + trials["p"][-cc[0]:], [0] + trials["t"][-cc[0]:], 1)
                dt = m*p+b

                # Assuming linear between last two test points tends to go unstable and dive into negative values
                #m = (trials["p"][-1]-trials["p"][-2])/(trials["t"][-1]-trials["t"][-2])
                #dt = (p-trials["p"][-1])/m+trials["t"][-1]

                # Assuming exponential tends to be unstable and diverges
                # dt = (dt/math.log(1 - (hits / hunt_depth))) * math.log(1-p)

        # This initializes the next hunt bundle
        hits=0
        if len(trials["p"])>2 and trials["p"][-1]>0:
            slow_hunt_growth = 1+abs(trials["p"][-1]-trials["p"][-2])/trials["p"][-1]
        if slow_hunt_growth > 1.2:
            slow_hunt_growth = 1.2
        hunt_depth=int(hunt_depth*slow_hunt_growth)

        # This runs a bundle of monte carlo runs at a specific model age to get a probability of how often the model has a complete path in that amount of time
        for j in range(int(hunt_depth)):
            run_history(tm, dt, dt, stop_at_hit=True)
            if "hit" in tm:
                hits=hits+1
            reset_history(tm)

        # This documents the last bundle of monte carlo runs
        trials["p"].append(hits/hunt_depth)
        trials["t"].append(dt)
        trials["histories"]=trials["histories"]+hunt_depth

        # This checks convergence status against the specified criteria to see if the current estimated time is "good enough"
        if len(trials["p"])>cc[0]:
            convergence_status = list_range(trials["p"][-cc[0]:]+[p])
            if verbose:
                print ("\r" + " "*40 + "\rp convergence: " + str(round(convergence_status, 4)) + " / " + str(cc[1]), end="")
            if convergence_status<cc[1]:
                convergence_status = list_range([abs((dt-x)/dt) for x in trials["t"][-cc[0]:]+[dt]])
                if verbose:
                    print (" - OK!, t convergence: " + str(round(convergence_status, 4)) + " / " + str(cc[2]), end="")
                if convergence_status<cc[2]:
                    if verbose:
                        print (" - OK!")
                    break
    if verbose:
        print ("Time for p of " + str(round(p, 2)) + " estimated at " + str(round(sum(trials["t"][-cc[0]:])/cc[0],2)) + " days")
    return sum(trials["t"][-cc[0]:])/cc[0], trials

def list_range(trials):
    # This function returns the maximum range between the values in a given list
    # Seems a little faster than using built-ins
    min_trial = trials[0]
    max_trial = trials[0]
    for i in trials:
        if i<min_trial:
            min_trial=i
        else:
            if i>max_trial:
                max_trial=i
    return max_trial-min_trial

def find_mean(tm, resolution=100, cc=(50,.005,.01), node_details=False, involvement=False, verbose=False, timeframe=-1):
    # Finds the mean time to compromise for a given trace model
    # resolution is how many steps to divide the cdf into to characterize it. 100 is pretty high, we've gotten away with fairly consistent results with a resolution as low as 5, particularly if you force a timeframe that's a little higher, like a p=.99 timeframe from find_time.
    # "cc" is the convergence criteria in terms of (trials, probability, time), where the results is considered converged when the past cc[0] trials are within the range of cc[2] (cc[1] does not apply for this)
    # The node_details parameter turns on and off storing data about every node. The purpose of the analysis is typically to get that node-level information, but it does take a little longer to do all the data stuff.
    # The verbose parameter gives lots of detailed output when True
    # Timeframe lets you skip the "find time" hunt that starts this function. That hunt takes time, and the value it picks can change the mean value a little. So if you're doing lots of "find mean" runs, it's handy to run "find time" first and then run "find mean" a few times. Also, it can improve the accuracy of the result if you set the timeframe really high.

    if verbose:
        if involvement:
            print ("\nFinding mean time to involvement")
        else:
            print ("\nFinding mean time to compromise")

    if timeframe==-1:
        if verbose:
            print ("Finding upper bound timeframe for p of " + str(round(1-1/(resolution+1), 4)))

        # Find the upper range time to run histories against
        timeframe = find_time(tm, 1-1/(resolution+1), verbose=True)[0]

    # Set up data structure for results
    trials={"t":[],"mu":[],"histories":0,"timeframe":timeframe,"resolution":resolution}
    if node_details:
        trials["nodes"]=[]
        for i in tm["graph"]:
            trials["nodes"].append({"id":i["id"],"results":{"mttc samples":[],"mtti samples":[]}})

    if verbose:
        print ("Running histories with timeframe of " + str(round(timeframe,2)) + " and dT of " + str(round(timeframe/resolution, 2)))

    # Run histories until the convergence criteria is met or a safety limit is exceeded, the upper end of the loop is arbitrary, and may be exceeded in very large models
    for safety in range(10000):

        # Find one hit age
        reset_history(tm)
        run_history(tm, timeframe, timeframe/resolution, involvement=involvement)
        trials["histories"]=trials["histories"]+1

        # Store the result for the overall graph
        trials["t"].append(tm["age"]+1)
        for i in tm["end"]:
            if "hit" in tm["graph"][i]:
                if tm["graph"][i]["hit"]<trials["t"][-1]:
                    trials["t"][-1]=tm["graph"][i]["hit"]
        if trials["t"][-1]==tm["age"]+1:
            trials["t"].pop()

        if len(trials["t"])>len(trials["mu"]):
            trials["mu"].append(fubini(trials["t"],trials["histories"]))

        # Store the per-node results if doing all nodes
        if node_details:
            for i in range(len(tm["graph"])):
                if "hit" in tm["graph"][i]:
                    trials["nodes"][i]["results"]["mttc samples"].append(tm["graph"][i]["hit"])
            if involvement:
                for i in range(len(tm["graph"])):
                    if "involved" in tm["graph"][i]:
                        trials["nodes"][i]["results"]["mtti samples"].append(tm["graph"][i]["involved"])

        # Check current data against convergence criteria
        if len(trials["mu"])>cc[0]:
            convergence_status = list_range([abs((trials["mu"][-1]-x)/trials["mu"][-1]) for x in trials["mu"][-cc[0]:]])
            if verbose:
                print ("\r" + " "*40 + "\rt convergence: " + str(round(convergence_status, 4)) + " / " + str(cc[2]), end="")
            if convergence_status<cc[2]:
                if verbose:
                    print (" - OK!")
                break
        else:
            print ("\r" + str(len(trials["mu"])) + " / " + str(cc[0]) + " initial samples.", end="")

    # Store result data in accessible dictionary
    trials["mttc"] = {}
    trials["mttc"]["mean"]=trials["mu"][-1]
    if involvement:
        trials["mtti"] = {}
        trials["mtti"]["mean"]=trials["mu"][-1]

    # Add per-node results
    if node_details:
        # Min and max result values are used to generate the color map in the plot module
        trials["mttc"]["max"]=0
        trials["mttc"]["min"]=-1
        for i in trials["nodes"]:
            if len(i["results"]["mttc samples"])>0:
                i["results"]["mttc"]=fubini(i["results"]["mttc samples"], trials["histories"])
                if i["results"]["mttc"]>trials["mttc"]["max"]:
                    trials["mttc"]["max"]=i["results"]["mttc"]
                if trials["mttc"]["min"]==-1 or i["results"]["mttc"]<trials["mttc"]["min"]:
                    trials["mttc"]["min"]=i["results"]["mttc"]
        if trials["mttc"]["max"]==trials["mttc"]["min"]:
            trials["mttc"]["min"]=0

        if involvement:
            trials["mtti"]["max"]=0
            trials["mtti"]["min"]=-1
            for i in trials["nodes"]:
                if len(i["results"]["mtti samples"])>0:
                    i["results"]["mtti"]=fubini(i["results"]["mtti samples"], trials["histories"])
                    if i["results"]["mtti"]>trials["mtti"]["max"]:
                        trials["mtti"]["max"]=i["results"]["mtti"]
                    if trials["mtti"]["min"]==-1 or i["results"]["mtti"]<trials["mtti"]["min"]:
                        trials["mtti"]["min"]=i["results"]["mtti"]
            if trials["mtti"]["max"]==trials["mtti"]["min"]:
                trials["mtti"]["min"]=0

    if verbose:
        print ("Overall mean estimated at " + str(round(trials["mu"][-1],2)) + " days")

    return trials["mu"][-1], trials

def fubini(samples_ref, sample_size=-1):
    # Takes an incomplete list of samples from an arbitrary probability distribution and applies a rough discrete version of fubini's theorem to approximate the expectation value
    # If we had a complete list of samples, this wouldn't be necessary, we could just average them to get the mean. However, this approach is necessary because we *aren't* actually sampling the real distribution, our samples are incomplete because we don't always run the models long enough to get a result. Since we do know that all the results we don't have are greater than the results we have, we can do this. In practice, this tends to give much more consistent results than just averaging the samples.

    samples=samples_ref.copy()
    if sample_size==-1:
        sample_size=len(samples)
    samples.sort()
    points={"x":[0],"y":[1]}
    dy = 1/sample_size
    for x in range(len(samples)):
        if samples[x] in points["x"]:
            points["y"][-1]=points["y"][-1]-dy
        else:
            points["x"].append(samples[x])
            points["y"].append(1-(x+1)*dy)

    # This is the part that adds "extra mass" for all the samples that went over the simulation timeframe
    if len(samples)<sample_size:
        m, b = numpy.polyfit(points["y"], points["x"], 1)
        if b < points["x"][-1]:
            b=points["x"][-1]
        points["x"].append(b)
        points["y"].append(0)

    expectation_value = 0
    for x in range(len(points["x"])-1):
        expectation_value = expectation_value + (points["x"][x+1]-points["x"][x])*(points["y"][x]+points["y"][x+1])*0.5

    return expectation_value
