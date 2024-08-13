import csv
import collections
import argparse

protocol_mapping = {"1": "icmp", "6": "tcp", "17": "udp"}
untagged = "untagged"

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("lookup")
    parser.add_argument("log")
    args = parser.parse_args()
    tag_count = collections.defaultdict(int)
    port_protocol_comb_count = collections.defaultdict(int)

    # Read look up table
    lookup_table = collections.defaultdict(dict)
    with open(args.lookup, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            lookup_table[row['protocol'].lower()][row['dstport']] = row['tag'].strip().lower()
    
    # Read log file
    with open(args.log, "r") as f:
        for row in f.readlines():
            data = row.split()
            port = data[6]
            protocol = data[7]
            if protocol not in protocol_mapping:
                print("Unknown protocol number", protocol)
                continue

            p = protocol_mapping[protocol]
            port_protocol_comb_count[(port, p)] += 1
            
            if p not in lookup_table:
                tag_count[untagged] += 1
                continue
        
            port_mapping = lookup_table[p]
            if port not in port_mapping:
                tag_count[untagged] += 1
                continue

            tag = port_mapping[port]
            tag_count[tag] += 1

    out_file = args.log.split('.')[0] + "_out.txt"
    with open(out_file, "w") as out:
        out.write("Tag Counts:\n")
        out.write("Tag \tCount\n")
        for t, c in tag_count.items():
            out.write(f'{t} \t{c}\n')

        out.write("\nPort/Protocol Combination Counts\n")
        out.write("Port \tProtocol \tCount\n")
        for k, v in port_protocol_comb_count.items():
            out.write(f'{k[0]} \t{k[1]} \t{v}\n')
            
