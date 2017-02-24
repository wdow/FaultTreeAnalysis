
import argparse
import re
import os
import sys
import subprocess
from sets import Set

def sanity_check(args):
    """Check to ensure infile exists, outfile is writeable"""
    if not os.path.isfile(args.infile):
        sys.exit("ERROR: Infile '" + args.infile + "' does not exist.")
        
    if not os.access(args.infile, os.R_OK):
        sys.exit("ERROR: User does not have permission to read file '" + args.infile +"'")
    
    if not os.access(args.outfile, os.W_OK):
        sys.exit("ERROR: User does not have permission to write to '" + args.outfile + "'")
        
        
#end sanity_check

def main(args):
    """"Main logic"""
    
    network_paths = '<src="(?P<src>.+)" dst="(?P<dst>.+)" route="(?P<route>.+)"/>'
    components = '\{(?P<uid>.+), "(?P<comp_name>.+)", "(?P<IP>.+)", vul="(?P<vul>.+)"\}'
    vulnerabilities = '{name="(?P<vul_name>.+)" score="(?P<weight>\d+)"}'

    fin = open(args.input)
    info = fin.read()

    paths = re.findall(network_paths, info)
    comps = re.findall(components, info)
    vuls = re.findall(vulnerabilities, info)

    fin.close()

    path_vulnerabilities = []

    for path in paths:
        path_vuls = Set([])
        path_comps = [x for x in path[2].split(',')]
        path_comps.append(path[0])
        print path_comps
        #grab vulnerabilities of the path itself
        for comp in comps:
            if(comp[0] in path_comps):
                comp_vuls = comp[3].split(',')
                for cv in comp_vuls:
                    for vul in vuls:
                        if(cv == vul[0]):
                            path_vuls.add(str(vuls.index(vul) + 1))
                        
        path_vulnerabilities.append(path_vuls)
    
    print path_vulnerabilities

    num_variables = str(len(vuls))
    num_clauses = str(len(vuls) + len(path_vulnerabilities))
    hard_weight = str(sum(int(x[1]) for x in vuls) + 1)

    print num_variables, num_clauses, hard_weight

    mi = open("maxino_input", "w")

    mi.write("p wcnf " + num_variables + " " + num_clauses + " "
        + hard_weight + "\n")
    
    for path in path_vulnerabilities:
        mi.write(hard_weight + " " + " ".join(path) + " 0\n")
    
    for vul in vuls:
        mi.write(str(vul[1]) + " " + "-" + str(vuls.index(vul) + 1) + " 0\n")
    
    mi.close()


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
    parser.add_argument('--size',
                        '-s',
                        type=int,
                        default=10,
                        help='''Specify the number of risk groups that should be found.''')
    args = parser.parse_args()
    
    sanity_check(args)
    
    main(args)
