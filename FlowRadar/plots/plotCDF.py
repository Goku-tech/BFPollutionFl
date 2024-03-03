import csv
import math

def read_file(filename):
    """
    Reading the flows from the files
    """
    flow = {}
    with open(filename,'r') as f:
        csvfile = csv.DictReader(f)
        for row in csvfile:
            flow[row['flow_id']] = float(row['packet_count'])

    print("Total flows :", len(flow))
    return flow


def accuracy(ground,mal):
    wr_dec = 0
    crr_dec = 0
    missing = 0
    pdf = {} # A list of the differences and the number of times it occurs. Helpful in creating a pdf
    for i in ground:
        if i not in mal:
            missing +=1
        else:
            if math.floor(abs(mal[i] - ground[i])) < 1:
                crr_dec+=1
            elif math.floor(abs(mal[i] - ground[i])) not in pdf:
                pdf[math.floor(abs(mal[i] - ground[i]))] = 1
                wr_dec+=1
            else:
                pdf[math.floor(abs(mal[i] - ground[i]))] +=1
                wr_dec+=1
    with open('cdf.csv', 'w') as f:
        for key in sorted(pdf.keys()):
            f.write("%s,%s\n"%(key,pdf[key]))
    
    print("\nWrongly decoded values: ", wr_dec)
    print("Correctly decoded values: ", crr_dec)
    print("missing values: ", missing)


print("For ground truth...")
ground = read_file('ground.csv')
print("\nFor malicious flows...")
decode = read_file('mal.csv')

accuracy(ground,decode)
