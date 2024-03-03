from scapy.all import *
import csv
import random
import time
import tracemalloc
from engine_base import *
import os
import time


def find_srclist(cd_g_truth):
	"""
	To find the src IP with the maximum number of flows and other related parameters
	"""

	flow_list = set() #set of unique flows
	src_IP = {} #Dictionary holding the src IPs and the max number of flows with that IP 
	pkt_size = [] #List of packet size
	for tup in cd_g_truth:
		flow_list.add(tuple(cd_g_truth[tup][0:5]))
		pkt_size.append(float(cd_g_truth[tup][5]))
		if cd_g_truth[tup][0] in src_IP:
			src_IP[cd_g_truth[tup][0]] +=1 #Incrementing the flow counts
		else:
			src_IP[cd_g_truth[tup][0]] = 1
	src = sorted(src_IP.items(),key=lambda x: x[1], reverse=True)#Finding the src IP with the most number of unique flows
	top_x_src_ip = [temp_src[0] for temp_src in src]
	print("Source IP: ",top_x_src_ip)
	#Returning the src IP with the max number of flows, the list of flows and the list of packet counts for each flow
	return top_x_src_ip,flow_list,pkt_size 

def attackers_BF(flowset,src,path):
	"""
	The BF used by the attacker to craft the malicius packets
	"""
	fl = flowset
	mal_flows_normal = {} #A parameter for debugging. STores the list of unique flows inserted
	pkt_count = 0
	
	# The attacker is allowed to sniff the traffic from the src IPs in src and based on them he populates his bloom filter
	# Currently only IPv4 is enabled. This is due to the fact that the datasets mostly usedd IPv4
	for pkt in PcapReader(path):
		if IP in pkt and pkt[IP].src in src:
			if TCP in pkt:
				flow_ID = [pkt[IP].src, pkt[IP].dst, str(pkt[TCP].sport), str(pkt[TCP].dport), str(pkt[IP].proto)]
			elif UDP in pkt:
				flow_ID = [pkt[IP].src, pkt[IP].dst, str(pkt[UDP].sport), str(pkt[UDP].dport), str(pkt[IP].proto)]
			else:
				flow_ID = [pkt[IP].src,pkt[IP].dst,'0','0',str(pkt[IP].proto)]
			fl.add_ct(flow_ID)
			k = tuple(flow_ID)
			pkt_count+=1
			if k not in mal_flows_normal:
				mal_flows_normal[k] = 0
			mal_flows_normal[k]+=1
	
	#Printing the total number of packets insertedd into the attacker's bloomfilter
	print("pkt_count: ",pkt_count)
	#Returning back the Attacker's BF 
	return fl

def unique_flow_creator(flowset,EXP_flows,malFlows,pkt_count,flow_list,filename):
	"""
	To craft unique (malicious flows + packet counts)
	"""

	fl = flowset #The BF of the attacker
	l=0
	k = 0
	pkt = 0
	mal_flows_unique = {} #To store the unique flows
	while l < math.ceil((EXP_flows*malFlows)/100):
		k+=1
		
		#Generating a random flow tuple
		src_IP = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
		dst_IP = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
		src_port = random.randint(0,65535)
		dst_port = random.randint(0,65535)
		proto = random.choice([6, 17]) # TCP,UDP
		item = [str(src_IP),str(dst_IP),str(src_port),str(dst_port),str(proto)]
		flow = tuple(item)

		#Finding the hash values of the flow
		x = convert_to_hex(item)
		key = [a for a in x][0]

		#If the flow does not exist in the original list of flows and is unique
		#In here the packets are inserted at random
		if flow not in mal_flows_unique and flow not in flow_list and key in fl:
			mal_flows_unique[flow] = pkt_count[pkt]
			l+=1
			pkt = (pkt+1)%len(pkt_count)
		print("Iteration = %s | Items found = %s"%(k,l),end="\r")
	
	#Writing the list of unique flows to a csv file
	with open(filename+'unique_flows.csv', 'w',newline='') as csv_file:  
		writer = csv.writer(csv_file)
		for key, value in mal_flows_unique.items():
			writer.writerow([key, value])
	
	print("[+] Creation of unique mal flows successful...")
	return mal_flows_unique,k

def read_mal_flows(filename,EXP_flows,malFlows):
	"""
	Reading from the list of already exisiting malicious flows.
	"""
	flow_list = [] # The list of malicious flows
	l = math.ceil(EXP_flows*malFlows/100)

	#Opening the file to read the malicious files
	with open(filename, 'r') as file:
		csvreader = csv.reader(file)
		for row in csvreader:
			if len(flow_list)>=l:
				break
			x = re.findall("'(.*?)'",row[0])
			flow_list.append(x)
	
	#Creating the required number of flows
	print("size of flowlist: ",len(flow_list))
	if len(flow_list)>0:
		random.shuffle(flow_list)
	return flow_list

def unique_flow_creator_v2(flowset,EXP_flows,malFlows,pkt_count,flow_list,filename):
	"""
	To craft unique (malicious flows + packet count) from a preexisting list of malicious flows.
	To be used together with read_mal_flows
	"""

	mal_flows_unique = {}
	pkt = 0
	for i in range(len(flowset)):
		mal_flows_unique[tuple(flowset[i])] = pkt_count[pkt]
		pkt =(pkt+1)%(len(pkt_count))
	
	# Printing the list of flows. Used for debugging
	for i in mal_flows_unique:
		print(i,"->",mal_flows_unique[i])
	
	#Storing the values to a csv file
	with open(filename+'unique_flow_tuple.csv', 'w',newline='') as csv_file:  
		writer = csv.writer(csv_file)
		for key, value in mal_flows_unique.items():
			writer.writerow([key, value])
	
	print("[+] Creation of unique mal flows successful...")
	return mal_flows_unique

def bucket(packet_size, exptVariant):
	"""
	Function to create the required packet size for each flow based on the experiments.
	"""
	packet_size.sort(reverse=True)
	
	#if 1 -- topx, we just sort the pcap based on packet size and return the result
	if exptVariant == 1:
		return packet_size
	
		#if 1 -- topx, we just sort the pcap based on packet size and return the result
	if exptVariant == 2:
		x = int(len(packet_size)/3)
		i=0
		bucketVar = []
		#In this case creating a list of bauckets from which the packets will then be inserted.
		while i <= len(packet_size):
			bucketVar.append(random.choice(packet_size[0:x]))
			bucketVar.append(random.choice(packet_size[x:2*x]))
			bucketVar.append(random.choice(packet_size[2*x:]))
			i+=3
		return bucketVar
	
	if exptVariant == 3:
		random.shuffle(packet_size)
		return packet_size

def mal_flows_create(mal_flows,pkt_count):
	"""
	If list of malicious flows already exists, then this function can be used to just attach the packets to the flows
	"""
	flow = {}
	i = 0
	#Currently only assigning the packet counts to the flow serially.
	for i in range(len(mal_flows)):
		flow[tuple(mal_flows[i])] = pkt_count[i]
		i = (i+1)%len(pkt_count)
	return flow

def bloomfilter():

	#Inputs from the cmd arguments.

	parser = argparse.ArgumentParser(description='engine reader')
	parser.add_argument('--pcap', metavar='<pcap file name>', help='pcap file to parse', required=True)
	parser.add_argument('--flows', metavar='<no of flows in the file>', help='flows incident on the bloom filter', required=True)
	parser.add_argument('--mal', metavar='<percent of malicious to be crafted>', help='percent of malicious to be crafted', required=True)
	parser.add_argument('--var', metavar='<variant of the experiment>', help='varaiant of experiment; 1 = topx, 2 = dsr, 3 = rnd', required=True)
	
	args = parser.parse_args()
	

	exptFlows = int(args.flows) #Expected number of flows, changes from dataset to dataset
	malFlows = float(args.mal) #Enter percentage of flows to be crafted
	dataSet = args.pcap #the name of the pcap file
	exptVariant = int(args.var) #varaiant of experiment;  1 = topx, 2 = dsr, 3 = rnd
	fpr = 0.01 #the FPR of the BF
	countingTableHash = 4 #the number of CT hash functions


	## FOR RESULT OUTPUT CLARITY
	exptVariantString = ""
	if exptVariant == 1:
		exptVariantString = "top"
	elif exptVariant == 2:
		exptVariantString = "dsr"
	elif exptVariant == 3:
		exptVariantString = "rnd"
	  
	##Convert Malicious flowpercent to string
	# print(type(args.mal))
	malFlowsString = args.mal
	malFlowsString = malFlowsString.replace('.','')
	runString = str(int(time.time()))

	outputString = "./results/queryOnly/" + exptVariantString + "/" + malFlowsString + "/" + runString + "/"
	os.makedirs(outputString, exist_ok=True)


	# dataSet = '120k_chicago.pcap' #the name of the pcap file
	# exptFlows = 25389 #Expected number of flows, changes from dataset to dataset
	# malFlows = float(input("Enter percentage of flows to be crafted: "))
	

	print(exptFlows, malFlows, dataSet, exptVariant, fpr, countingTableHash, outputString)
	
	# os.exit()




	# Creating two BF: Normal and the attacker's
	fl = Flowset(exptFlows,fpr,countingTableHash)
	mal_fl = Flowset(exptFlows,fpr,countingTableHash)

	#Inserting the flows from the pcap and creating a ground truth. This is the control setup
	g_truth,flowset = insert_flows(dataSet,{},0,fl,outputString+'ground.csv')

	#Control's the attacker's adverserial strength
	src,flow_list,pkt_size = find_srclist(g_truth)

	#The packet count of the malicious flows
	bucket_pkt = bucket(pkt_size, exptVariant)

	#Populating the attacker's BF
	mal_flowset = attackers_BF(mal_fl,src,dataSet)

	#Crafting unique flows
	mal_flows,check_iterations_mal = unique_flow_creator(mal_flowset,exptFlows,malFlows,bucket_pkt,flow_list,outputString)

	#the corrfupted BF
	final = Flowset(exptFlows,fpr,countingTableHash)

	#Inserting the malicious flows together with the benign flow
	final_mal_truth,en_mal_flowset = insert_flows(dataSet,mal_flows,malFlows,final,outputString+'corrupted.csv')
	
	#Calling the singledecode and CounterDecode to the BF. 
	Decode(en_mal_flowset, outputString)
	print("Size of BF:",final.num_bits)
	print("No of BF hash functions ",final.num_slices)
	print("Total iterations for mal:",check_iterations_mal)


if __name__ == "__main__":
	bloomfilter()
