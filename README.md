# FaultTreeAnalysis
A project to take in dependency data, construct a Boolean satisfiability formula out of it and find cutsets of vulnerabilities that
could take down the whole service should they trigger simultaneously.

To run the script, make sure ft_analyzer and its modules sat_solver_manager.py and dependency_file_manager.py are in the same directory.
Run ft_analyzer on an input dependency data file, optionally specifying an output file or a number of cutsets to receive.
Make sure the file ft_analyzer is executable, the output file can be written to, and the inputfile can be read.

Example:

bash-$ ./ft_analyzer example-input -r 3 -o outfile
bash-$ cat outfile
<?xml version="1.0" ?>
<cutsets>
	<cutset items="v2" weight="0.2"/>
	<cutset items="v1, v4" weight="0.075"/>
	<cutset items="v1, v5" weight="0.0525"/>
</cutsets>
bash-$

Specifying an r value greater than the number of cutsets that exist in the file will print an error message and
then dump all the found cutsets.

Example:

bash-$ ./ft_analyzer example-input -r 100 -o outfile
ERROR: SAT solver failed on repetition 4.
bash-$ cat outfile
<?xml version="1.0" ?>
<cutsets>
	<cutset items="v2" weight="0.2"/>
	<cutset items="v1, v4" weight="0.075"/>
	<cutset items="v1, v5" weight="0.0525"/>
	<cutset items="v3" weight="0.05"/>
</cutsets>
bash-$

To run the tests in the example_data folder, run the script test_script.sh in the same directory as ft_analyzer, its modules and the
three input files.  There is a test of 10,000 cutsets at the end, so that test takes some time.  The longest observed time to solve
such a test was 16 hours.

To run the tests in the stress_testing folder, run the script generate_bigfiles.sh in the same directory as ft_analyzer
and its modules.  Note that this method will generate three entirely new input files for the analyzer to solve, so the outputs
won't be the same.  The three files the script created that match to the output files in the folder are included for
reference.  This script also takesan extremely long time to run, since it runs three 10,000 cutset tests.
