import argparse
from scanlib import *

parser = argparse.ArgumentParser()
parser.add_argument("--domain", help="Domain to scan")
parser.add_argument("--proxy", help="Proxy to store requests")
parser.add_argument("--dnsonly", help="No ip webscan", action='store_true')
parser.add_argument("--nod", help="No discovering")
parser.add_argument("--noe", help="No entering sites")

args = parser.parse_args()
exec_args = []
domain = args.domain
proxy = args.proxy
nod = args.nod
noe = args.noe
dnsonly = args.dnsonly

all_results = {}

#os._exit(0)
print(create_artifacts(domain))
execute_worker(all_results, 'subfinder -d {0} -silent'.format(domain), 'subfinder')
execute_worker(all_results, 'dnsx -silent -resp -d {0} -w !assets\\5000.txt'.format(domain), 'dnsx')
all_results['DNS'] = list(set(all_results['subfinder']) | set(get_column(all_results['dnsx'])))
print('DNS')
print(all_results['DNS'])

execute_worker(all_results, 'dnsx -silent -resp', 'DNS_IP', stdin_data=list(all_results['DNS']))
print('-------------------------------------')
print(list(all_results['DNS_IP']))
execute_worker(all_results, 'smap -iL - -oP -', 'PORTS', stdin_data=list(all_results['DNS']))
print("PORTS")
print(all_results['PORTS'])


nmap_results = nmap_services_scan(all_results, all_results['PORTS'])
all_results['SERVICES'] = nmap_results_for_cve_list(nmap_results)

print("SERVICES")
print(all_results['SERVICES'])

for item in all_results['SERVICES']:
    html_logger.info(item)

cpe_list, service_further_scan_list = scan_list_converting(all_results['SERVICES'])

#cpe_list = parse_to_cpe(cpe_list)
#print("cpe_list")
#print(cpe_list)
print(service_further_scan_list)
log_intermediate(service_further_scan_list)
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
        non_http_ports.append((item[0], item[1]))

print(http_ports)
print(https_ports)
print(non_http_ports)
log_intermediate(http_ports)
log_intermediate(https_ports)
log_intermediate(non_http_ports)
all_results['DNS_IP'] = links_ip_to_dns(all_results['DNS_IP'])

if args.proxy != None:
    web_init_recon(all_results, 'https', https_ports, dns_only=dnsonly, proxy=proxy)
    web_init_recon(all_results, 'http', http_ports, dns_only=dnsonly, proxy=proxy)
else:
    web_init_recon(all_results, 'https', https_ports, dns_only=dnsonly, proxy=proxy)
    web_init_recon(all_results, 'http', http_ports, dns_only=dnsonly, proxy=proxy)

inner_urls, outer_urls = web_extracting(all_results)
print('inner_urls')
print(inner_urls)
print('outer_urls')
print(outer_urls)
log_intermediate(all_results)
#print(all_results)

#for service in service_further_scan_list:
#    execute_worker('ffuf -mc all -w 5000.txt -H "Host: FUZZ.fultek.com.tr" -u https://fultek.com.tr -o usual.txt','vhost_dns')
#    execute_worker('ffuf -mc all -w vhost_ips.txt -H "Host: FUZZ" -u https://fultek.com.tr -o ','vhost_ips')
#execute_worker('echo "cpe:/a:apache"| csv2cpe -x -lower -cpe_part=1 -cpe_vendor=2 -cpe_product=3 -cpe_version=4 -cpe_update=5 -cpe_edition=6 -cpe_language=7', stdin_data=list(all_results['DNS']))
#execute_worker('echo "cpe:/a:apache"| cpe2cve -cpe 1 -e 1 -cve 1  CVEs\\nvdcve-1.1-2002.json.gz', stdin_data=list(all_results['DNS']))
