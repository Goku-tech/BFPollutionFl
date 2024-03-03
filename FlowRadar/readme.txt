How to run the code 

The following are the three important files: engine.py, queryOnly.py and chosenInsertion.py
1. engine.py is the base python file which contains engine
2. queryOnly.py is specific to a particular type of attack (QOA).
3. chosenInsertion.py is specific to a particula type of attack (CIA).

To start the experiment, execute either queryOnly.py or chosenInsertion.py based on which type of attack you want to perform. For example, to run the query only code, run the following command. The options are explained below:

> sudo python3 queryOnly.py --pcap 110k_24k_caida.pcap --flows 24100 --mal 0 --var 1

--pcap = input packet trace file
--flows = number of expected flows (this is used to fix the bloom filter size) 
--mal = percentage of malicious flows
--var = variant of the experiment. 1: topx variant, 2: distributed random, 3: random

Once the above code is executed, please wait for some time (30 to 60 mins) for the decoding process to finish. The results are stored in a separate folder called resutls. To analyze the results, open the file plotMetrics.py from the folder plots. You need to edit the following two lines at the end of the code.

ground = read_file('/home/netx1/secinfra/SecInfra-BloomFilterPollution/FlowRadar/engine/results/queryOnly/top/0/1708256038/ground.csv')
decode = read_file('/home/netx1/secinfra/SecInfra-BloomFilterPollution/FlowRadar/engine/results/queryOnly/top/0/1708256038/mal.csv')

Replace this part "/home/netx1/secinfra/SecInfra-BloomFilterPollution/FlowRadar/engine/results/queryOnly/top/0/1708256038/" with the path to your newly generated results. The output will give you the number of correctly decoded flows, incorrectly decoded flows and undecodable flows.

In case it takes too much time, then please use this command to see if the process is still running: pgrep -lf python
Kill the process using this: kill -9 PID (replace PID with the process ID from the above command)


Flows of function calls: 

queryOnly.py:Bloomfilter()  ---> engine.py:Flowset() ---> engine.py:_setup() ---> engine.py:make_hashfuncs()


