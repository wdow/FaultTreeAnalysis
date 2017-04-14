#! /usr/bin/env python

import argparse
import re
import os
import sys
import math
from tempfile import NamedTemporaryFile
from sets import Set
from subprocess import check_output, CalledProcessError
import xml.etree.ElementTree as ET

#TODO: Sanity Checking

def sanity_check(args):
    """Check to ensure infile exists, outfile is writeable,
    and SAT-solver is useable"""
    if not os.path.isfile(args.infile):
        sys.exit("ERROR: Infile '" + args.infile + "' does not exist.")
        
    if not os.access(args.infile, os.R_OK):
        sys.exit("ERROR: User does not have permission to read file '" + args.infile +"'")
    
    if os.path.isfile(args.outfile) and not os.access(args.outfile, os.W_OK):
        sys.exit("ERROR: User does not have permission to write to '" + args.outfile + "'")
        
    if not os.access(args.satsolver, os.X_OK):
        sys.exit("ERROR: User does not have permission to run SAT-solver '" + args.satsolver +"'")
        
#end sanity_check

def adjust_weight(weight):
    """Helper function to convert vulnerability weights into a
    form maxino can actually use"""
    return int((-100) * math.log(float(weight)/float(20)))
#end adjust_weight
    
def assemble_SATinput(vul_dict, vul_to_int, vul_adjusted, path_vuls, cutsets):
    """Create a tempfile in the format necessary for maxino to run"""
    mi = NamedTemporaryFile()

    hard_weight = str(sum(vul_adjusted.values()) + 1)

    #write file header
    mi.write("p wcnf " + str(len(vul_dict)) + " " + str(len(path_vuls) +
        len(vul_dict) + len(cutsets)) + " " + hard_weight + "\n")
    
    #write the vulnerabilities, preappended with the hard weight
    for path in path_vuls:
        mi.write(hard_weight)
        for vul in path:
            if vul != '':
                mi.write(" " + vul_to_int[vul])
        mi.write(" 0\n")
        
    #write the negation of any cutsets already found, so that they
    #will be discounted from this round of SAT-solving
    for ct in cutsets:
        mi.write(hard_weight)
        for vul in ct:
            if vul != '':
                mi.write(" -" + vul_to_int[vul])
        mi.write(" 0\n")
    
    #write the clauses weighting each vulnerability
    for vul in vul_adjusted:
        mi.write(str(vul_adjusted[vul]) + " -"
            + vul_to_int[vul] + " 0\n")
        
    return mi
#end assemble_SATinput

def main(args):
    """"Main logic"""
    
    #regex templates to pick out info from input file
    network_paths = '<src="(?P<src>.+)" dst="(?P<dst>.+)" route="(?P<route>.+)"/>'
    components = '\{(?P<uid>.+), "(?P<comp_name>.+)", "(?P<IP>.+)", vul="(?P<vul>.*)"\}'
    vulnerabilities = '{name="(?P<vul_name>.+)" score="(?P<weight>\d+)"}'

    fin = open(args.infile)
    info = fin.read()

    paths = re.findall(network_paths, info)
    comps = re.findall(components, info)
    vuls = re.findall(vulnerabilities, info)
    
    """print paths
    print comps
    print vuls"""
    
    
    if not paths or not comps or not vuls:
        sys.exit("ERROR: Malformed infile '" + args.infile + "'")
    
    comp_dict = dict(zip([x[0] for x in comps], [x[3] for x in comps]))
    vul_dict = dict(vuls)
    vul_to_int = dict(zip([x[0] for x in vuls],
        [str(vuls.index(x) + 1) for x in vuls]))

    fin.close()

    path_vuls = []

    comp_tracker = 1
    #comps_to_ints = {}
    comps_to_weights = []

    #figure out the vulnerabilities in each path
    for path in paths:
        line_vuls = Set([])
        path_comps = [x for x in path[2].split(',')]
        path_comps.append(path[0])

        #grab vulnerabilities of the path itself
        for comp in path_comps:
            v = comp_dict[comp].split(',')
            for vul in v:
                if vul not in line_vuls:
                    line_vuls.add(vul)
            #print 'line vuls:'
            #print line_vuls
        vul_adjusted = {}
        for vul in vul_dict:
            vul_adjusted[vul] = adjust_weight(int(vul_dict[vul]))
            
        path_vuls.append(line_vuls)

    #now generate maxino input as a tempfile
    mi = assemble_SATinput(vul_dict, vul_to_int, vul_adjusted, path_vuls, [])
        
    #now run the maxino SAT-solver on the tempfile to find a risk group,
    #then append a line to the tempfile to remove that old risk group from
    #consideration for further runs
    optimum_result = 's OPTIMUM FOUND\nv (?P<opt>.+)'
    out = open(args.outfile, "w")

    root = ET.Element("cutsets")
    cutsets = []
    
    for rep in range(0, args.reps):
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
        
        cutset = []
        #reported weight is a slight permutation of the actual
        #vulnerability weights, so that what is reported to the user
        #is ranked correctly
        reported_weight = 1
        vul_config = [int(x) for x in rg[0].split(" ")]
        #convert the maxino output back into vulnerability names
        for v in vul_config:
            if(v > 0):
                trig_vul = list(vul_to_int.keys())[list(vul_to_int.values()).index(str(v))]
                cutset.append(trig_vul)
                reported_weight = reported_weight * (float(vul_dict[trig_vul])/20.0)
        cutsets.append(cutset)
        
        ET.SubElement(root, "cutset", items=', '.join(cutset), weight=str(reported_weight))
        
        #recreate the tempfile with the old risk group as a high-weighted clause
        #to ensure the same risk group won't be picked again
        mi.close()
        mi = assemble_SATinput(vul_dict, vul_to_int, vul_adjusted, path_vuls, cutsets)

    tree = ET.ElementTree(root)
    tree.write(out)
    
    #close tempfile, outfile
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
