
#================================================================
#
#   sat_solver_manager.py -- module to handle functions
#   pertaining to the SAT-solving program
#
#   Written by Will Dower (william.dower@yale.edu) for Yale
#   CPSC 490
#
#   May 3rd, 2017
#
#================================================================

from tempfile import NamedTemporaryFile
from subprocess import check_output, CalledProcessError
import sys
import re

import dependency_file_manager as dfm

def assemble_SATinput(path_vuls, vuls, vul_adjusted, cutsets):
    """Create a tempfile in the format necessary for maxino to run"""
    
    vul_dict = dict(vuls)
    vul_to_int = dfm.vuls_to_int(vuls)
    
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

def run_satsolver(tempfile):
    '''function to run maxino on an infile and handle to output'''

    try:
        maxino_output = check_output(["./" + "maxino-2015-k16-static", tempfile.name])
    except CalledProcessError as ex:
        maxino_output = ex.output
        returncode = ex.returncode
            
        if returncode == 20:
            return "fail"
        
        if returncode != 10: # some other error happened
            raise
            
    return maxino_output
#end run_satsolver

def process_output(maxino_output, vul_dict, vul_to_int):
    '''function to convert maxino's output back into the names of 
    vulnerabilities'''
    
    optimum_result = 's OPTIMUM FOUND\nv (?P<opt>.+)'
    
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
    #for cutsets with many components, reported_weight might become too
    #small to be useful, so normalize it to 1
    if reported_weight < 1e-5:
        reported_weight = 1
        
    return [cutset, reported_weight]
#end process_output
