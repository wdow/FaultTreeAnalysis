
#================================================================
#
#   dependency_file_manager.py -- module to handle functions
#   pertaining to dependency files
#
#   Written by Will Dower (william.dower@yale.edu) for Yale
#   CPSC 490
#
#   May 3rd, 2017
#
#================================================================

import re
import sys
from sets import Set
import math

def process_dependency_data(infile):
    '''use regex matching to find path, component, and vulnerability info'''
    #regex templates to pick out info from input file
    network_paths = '<src="(?P<src>.+)" dst="(?P<dst>.+)" route="(?P<route>.+)"/>'
    components = '\{(?P<uid>.+), "(?P<comp_name>.+)", "(?P<IP>.+)", vul="(?P<vul>.*)"\}'
    vulnerabilities = '{name="(?P<vul_name>.+)" score="(?P<weight>\d+)"}'

    #grab input from file
    fin = open(infile)
    info = fin.read()
    fin.close()

    #grab dependency data from input
    paths = re.findall(network_paths, info)
    comps = re.findall(components, info)
    vuls = re.findall(vulnerabilities, info)
    
    return [paths, comps, vuls]
#end process_dependency_data

def comps_to_dict(comps):
    '''helper function to strip extraneous info from component listings and
    nicely package them in a dict'''
    return dict(zip([x[0] for x in comps], [x[3] for x in comps]))
#end comps_to_dict
    
def vuls_to_int(vuls):
    '''helper function to assign a number to a list of items such that
    they can be processed by maxino'''
    return dict(zip([x[0] for x in vuls],
        [str(vuls.index(x) + 1) for x in vuls]))
#end vuls_to_int
        
def adjust_weight(weight):
    """Helper function to convert vulnerability weights into a
    form maxino can actually use"""
    return int((-100) * math.log(float(weight)/float(20)))
#end adjust_weight

def determine_path_vulnerabilities(paths, comps, vuls):
    '''function to find all the vulnerabilites associated with the components of a
    particular path'''
    comp_dict = comps_to_dict(comps)
    vul_dict = dict(vuls)
    vul_to_int = vuls_to_int(vuls)

    path_vuls = []
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
        #adjust vulnerability score so that it can work with the SAT-solver
        vul_adjusted = {}
        for vul in vul_dict:
            vul_adjusted[vul] = adjust_weight(int(vul_dict[vul]))
            
        path_vuls.append(line_vuls)
        
    return [path_vuls, vul_adjusted]
#end determine_path_vulnerabilities
