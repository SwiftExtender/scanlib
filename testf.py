import sys
import csv
from datetime import datetime
from collections import defaultdict

def get_csv_column(res_file, column_name):
    res_columns = defaultdict(list)
    with open(res_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            for (k,v) in row.items():
                res_columns[k].append(v)
    return res_columns[column_name]

def links_ip_to_dns(dnsx_output):
    ip_to_dns = dict()
    for line in dnsx_output:
        dns, ip = line.split()
        ip = ip[1:-1]
        if ip not in ip_to_dns.keys():
            ip_to_dns[ip] = [dns]
        else:
            ip_to_dns[ip].append(dns)
    return ip_to_dns

#print(links_ip_to_dns(sys.stdin))
print(get_csv_column('D:\\!automation!\\scan_results\\22-09-2023-224217-results_za\\ffuf_results\\95.217.45.348022-09-2023-224257.csv','url'))