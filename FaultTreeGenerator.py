
import argparse
import re
import os
import sys
from tempfile import NamedTemporaryFile
from sets import Set
from subprocess import check_output, CalledProcessError

def sanity_check(args):
    """Check to ensure infile exists, outfile is writeable, and SAT-solver is useable"""
    if not os.path.isfile(args.infile):
        sys.exit("ERROR: Infile '" + args.infile + "' does not exist.")
        
    if not os.access(args.infile, os.R_OK):
        sys.exit("ERROR: User does not have permission to read file '" + args.infile +"'")
    
    if os.path.isfile(args.outfile) and not os.access(args.outfile, os.W_OK):
        sys.exit("ERROR: User does not have permission to write to '" + args.outfile + "'")
        
    if not os.access(args.satsolver, os.X_OK):
        sys.exit("ERROR: User does not have permission to run SAT-solver '" + args.satsolver +"'")
        
        
#end sanity_check

def lookup(ls, comp):
    """helper function, finds if comp is present in a nested list and returns
    that nested list's index"""
    for entry in ls:
        if (entry[0] == comp):
            return ls.index(entry) + 1
    return -1
    
def get_weight(ls, comp):
    """helper function, finds weight of specified comp in nested list"""
    for entry in ls:
        if (entry[0] == comp):
            return entry[1]
    return -1

def main(args):
    """"Main logic"""
    
    network_paths = '<src="(?P<src>.+)" dst="(?P<dst>.+)" route="(?P<route>.+)"/>'
    components = '\{(?P<uid>.+), "(?P<comp_name>.+)", "(?P<IP>.+)", vul="(?P<vul>.+)"\}'
    vulnerabilities = '{name="(?P<vul_name>.+)" score="(?P<weight>\d+)"}'

    fin = open(args.infile)
    info = fin.read()

    paths = re.findall(network_paths, info)
    comps = re.findall(components, info)
    vuls = re.findall(vulnerabilities, info)

    fin.close()

    path_vulnerabilities = []

    comp_tracker = 1
    #comps_to_ints = {}
    comps_to_weights = []

    for path in paths:
        path_vuls = Set([])
        path_comps = [x for x in path[2].split(',')]
        path_comps.append(path[0])
        
        '''for comp in path_comps:
            if comp not in comps_to_ints:
                comps_to_ints[comp] = comp_tracker
                comp_tracker += 1'''
        #print "map: "
        #print comps_to_ints
        
        #need to add up vuls associated with each comp to get a weight for that comp
        
        #print path_comps
        #grab vulnerabilities of the path itself
        for comp in comps:
            weight = 0
            if(comp[0] in path_comps):
                comp_vuls = comp[3].split(',')
                for cv in comp_vuls:
                    
                    for vul in vuls:
                        if(cv == vul[0]):
                            weight += int(vul[1])
                            #print weight
                if [comp[0], weight] not in comps_to_weights:
                    comps_to_weights.append([comp[0], weight])
        
        path_vulnerabilities.append(path_comps)
                        
    #print "int tags: "
    #print comps_to_ints
    #print "weights: "
    #print comps_to_weights
    
        
    
    #print path_vulnerabilities

    num_variables = str(len(comps_to_weights))
    num_clauses = str(len(comps_to_weights) + len(path_vulnerabilities))
    hard_weight = str(sum(int(vul[1]) for vul in vuls ) + 1)
    
    #print hard_weight

    #print num_variables, num_clauses, hard_weight

    #now generate maxino input as a tempfile
    mi = NamedTemporaryFile()

    mi.write("p wcnf " + num_variables + " " + num_clauses + " "
        + hard_weight + "\n")
    
    #write the components, preappended with the hard weight
    for path in path_vulnerabilities:
        mi.write(hard_weight)
        for comp in path:
            mi.write(" " + str(lookup(comps_to_weights, comp)))
        mi.write(" 0\n")
        #mi.write(hard_weight + " " + " ".join(path) + " 0\n")
    
    #write the clauses weighting each component, preappended by hard weight minus component weight
    for comp in comps:
        mi.write(str(int(hard_weight) - get_weight(comps_to_weights, comp[0])) + " -"
            + str(lookup(comps_to_weights, comp[0])) + " 0\n")
        #mi.write(str(vul[1]) + " " + "-" + str(vuls.index(vul) + 1) + " 0\n")
        
    #now run the maxino SAT-solver on the tempfile to find a risk group,
    #then append a line to the tempfile to remove the old risk group from
    #consideration
    optimum_result = 's OPTIMUM FOUND\nv (?P<opt>.+)'
    out = open(args.outfile, "w")

    
    for x in range(0, args.reps):
        mi.seek(0)
        test= mi.read()
        print test
        mi.seek(0)
        #run maxino SAT-solver on the tempfile
        try:
            maxino_output = check_output(["./" + args.satsolver, mi.name])
        except CalledProcessError as ex:
            maxino_output = ex.output
            returncode = ex.returncode
            if returncode != 10: # some other error happened
                raise
    
        rg = re.findall(optimum_result, maxino_output)
        cutset = ""
        total_weight = 0
        component_config = [int(x) for x in rg[0].split(" ")]
        for i in component_config:

            if(i > 0):
                cutset += comps_to_weights[i-1][0]
                total_weight += comps_to_weights[i-1][1]
            
            
        out.write("<cutset=\"" + cutset + "\" weight=\"" + str(total_weight)
            + "\"/>\n")
    
    #close tempfile, which deletes it
    mi.close()
    out.close()

#end main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""Takes in dependency information about a system and 
        uses the Maxino SAT solver to find the system's risk groups.""")
    parser.add_argument('--infile',
                        '-i',
                        type=str,
                        default="example-input",
                        help='''Designate an input file with the target 
                                system's dependency information.''')
    parser.add_argument('--outfile',
                        '-o',
                        type=str,
                        default="risk_groups",
                        help='''Name an output file to store the risk group data.''')
    parser.add_argument('--satsolver',
                        '-s',
                        type=str,
                        default="maxino-2015-k16-static",
                        help='''Name a version of the Maxino SAT-solver to use
                         in processing the dependency information.''')
    parser.add_argument('--reps',
                        '-r',
                        type=int,
                        default=1,
                        help='''Specify the number of risk groups that should be found.''')
    args = parser.parse_args()
    
    sanity_check(args)
    
    main(args)
