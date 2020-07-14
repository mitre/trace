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
from . import transform, montecarlo

def mtti_from_json(input_json):
    # This function is for a simple json string-based interface

    # This loads the input JSON into a node-net model, which represents the literal network architecture
    nn = json.loads(input_json)

    # This applies the echo transform, expanding the components into a threat concept graph with edge weights reflecting the mean vulnerability discovery rates
    tm = transform.nn_to_tm(nn)

    # This runs a monte carlo against the threat concept graph
    mtti, mtti_results = montecarlo.find_mean(tm, node_details=True, involvement=True, cc=(100,.01,.01))

    # This loads the results data from the threat concept graph back into the network architecture ("node net") model
    nn = transform.tm_results_to_nn(tm, mtti_results, nn)

    # This returns the node net input model with result data attached
    return json.dumps(nn)
