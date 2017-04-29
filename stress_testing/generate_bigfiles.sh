#generate three large inputs for the FTG, then run them through
#the FTG and save the output, save runtimes in log

python bigfile-generator bf1
python bigfile-generator bf2
python bigfile-generator bf3

echo bf1 run > timelog

time python FaultTreeGeneratorModified.py bf1 -o output1 -r 10000 2>> timelog

echo bf2 run >> timelog

time python FaultTreeGeneratorModified.py bf2 -o output2 -r 10000 2>> timelog

echo bf3 run >> timelog

time python FaultTreeGeneratorModified.py bf3 -o output3 -r 10000 2>> timelog
