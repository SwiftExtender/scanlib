import argparse
from scanlib import *

parser = argparse.ArgumentParser()
parser.add_argument("--file", help="File with subnets to scan")
parser.add_argument("--proxy", help="Proxy to store requests")


args = parser.parse_args()
exec_args = []
file = args.file
proxy = args.proxy

all_results = {}

execute_worker(all_results, 'naabu -p 20-30000 -silent -rate 500 -stream -output naabulog_scan.txt', 'PORTS', stdin_data=list(all_results['DNS']))
print("PORTS")
print(all_results['PORTS'])


nmap_results = nmap_services_scan(all_results, all_results['PORTS'])
all_results['SERVICES'] = nmap_results_for_cve_list(nmap_results)

print("SERVICES")
print(all_results['SERVICES'])

for item in all_results['SERVICES']:
    html_logger.info(item)

http_ports = []
https_ports = []
non_http_ports = []

print('Defining port types for further scan')

for item in service_further_scan_list:
    print(item)
    if item[2] == 'http' and item[3] != 'ssl':
        http_ports.append((item[0], item[1]))
    elif (item[2] == 'https') or (item[2] == 'http' and item[3] == 'ssl'):
        https_ports.append((item[0], item[1]))
    else:
        non_http_ports.append((item[0], item[1]
