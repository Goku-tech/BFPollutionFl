import csv

def read_file(filename):
    """
    Reading the flows from file
    """

    flow = {}
    with open(filename,'r') as f:
        csvfile = csv.DictReader(f)
        for row in csvfile:
            flow[row['flow_id']] = float(row['packet_count'])

    print("Total flows :", len(flow))
    return flow


def accuracy(ground,mal):
    """
    Printing the parameters for the accuracy calcualtion
    """

    wr_dec = 0
    crr_dec = 0
    missing = 0
    for i in ground:
        # If the flow is not in mal
        if i not in mal:
            missing +=1
        else:
            # if the difference in packet counts is more than 1, we treat the flow as wrongly decoded.
            if abs(mal[i] - ground[i]) >=1:
                wr_dec +=1
            else:
                crr_dec+=1
    
    print("\nWrongly decoded values: ", wr_dec)
    print("Correctly decoded values: ", crr_dec)
    print("missing values: ", missing)


print("For ground truth...")
ground = read_file('/home/netx3/secinfra/SecInfra-BloomFilterPollution/FlowRadar/engine/results/queryOnly/top/10/1709044748/ground.csv')
print("\nFor malicious flows...")
decode = read_file('/home/netx3/secinfra/SecInfra-BloomFilterPollution/FlowRadar/engine/results/queryOnly/top/10/1709044748/mal.csv')

accuracy(ground,decode)
