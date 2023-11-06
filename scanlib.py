import os
import socket
import subprocess
import csv
from datetime import datetime
from collections import defaultdict
from libnmap.parser import NmapParser
import html_logger

target_domain = ['']
foldername = ['']
user_agent = 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36'

def write_to_file(dir: str, filename: str, content: list) -> bool:
    try:
        with open(dir + os.sep + filename, 'w') as f:
            f.writelines(line.strip() + '\n' for line in content)
        return True
    except:
        return False

def filter_list(item, array: list) -> list:
    #print()
    res = []
    for i in array:
        if item in i:
            print(i)
            res.append(i)
    return res

def uniq_and_sort(array: list) -> list:
    return sorted(list(set(array)))

def create_artifacts(domain):
    try:
        target_domain[0] = domain
        ctime_str = datetime.now().strftime('%d-%m-%Y-%H%M%S')
        print("Current working directory: {0}".format(os.getcwd()))
        foldername[0] = os.getcwd() + os.sep + 'scan_results' + os.sep + ctime_str + '-results_' + domain[:2]
        print(foldername)
        os.makedirs(foldername[0])
        html_logger.setup('Scan results', filename=foldername[0] + os.sep + 'results.html', version="0.0.1")
        create_folder_in_scan_folder('nmap_results')
        create_folder_in_scan_folder('ffuf_results')
        create_folder_in_scan_folder('hakrawler_results')
        create_folder_in_scan_folder('katana_results')
        create_folder_in_scan_folder('dalfox_results')
        create_folder_in_scan_folder('url_results')
        create_folder_in_scan_folder('url_prep_results')

        #create_folder_in_scan_folder('cariddi_results')
        return foldername[0]
    except Exception as e:
        print(e)
        return False

def log_intermediate(mes) -> bool:
    try:
        html_logger.err('-'*20)
        html_logger.err(mes)
        html_logger.err('-' * 20)
        return True
    except:
        return False

def log_worker(all_results: dict, res, category) -> bool:
    try:
        html_logger.dbg(gen_timestamp())
        html_logger.dbg('----' + category + '----')
        html_logger.dbg('Count of values: {0}'.format(str(len(res))))
        unique_res = list(set(res))
        html_logger.dbg('Unique values: {0}'.format(str(len(unique_res))))
        for item in unique_res:
            html_logger.info(item)
        if category in all_results.keys():
            for item in unique_res:
                all_results[category].append(item)
        else:
            all_results[category] = unique_res
        return True
    except:
        return False

def create_folder_in_scan_folder(folder: str) -> bool:
    try:
        os.makedirs(foldername[0] + os.sep + folder)
        print('Folder {0} created'.format(foldername[0] + os.sep + folder))
        return True
    except:
        return False

def gen_timestamp() -> str:
    return datetime.now().strftime('%d %H:%M:%S')

def stdin_data_handle(proc, stdin_data, lower_flag):
    if stdin_data != []:
        if lower_flag:
            res = str(proc.communicate(input="{}".format("\n".join(stdin_data), encoding ='ascii'))[0]).lower().splitlines()
        else:
            res = str(proc.communicate(input="{}".format("\n".join(stdin_data), encoding ='ascii'))[0]).splitlines()
    else:
        if lower_flag:
            res = str(proc.communicate()[0]).lower().splitlines()
        else:
            res = str(proc.communicate()[0]).splitlines()
    return res

def execute_worker(all_results: dict, command: str, category: str, lower_flag=True, stdin_data = [], stdout_file='', output_type='list', no_stdout = False, wait=True, logging=True, timeout=0):
    if no_stdout:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL)
        print(command)
        html_logger.warn(command)
        if wait:
            print(proc.communicate(timeout=600))
            print(proc.returncode)
        return True #ignore stdout operations, fix later
    else:
        #print(os.getcwd())

        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        print(command)
        #html_logger.warn(command)
        res = stdin_data_handle(proc, stdin_data, lower_flag)
        if stdout_file != '':
            f = open(stdout_file, 'w')
            f.writelines(res)
            f.close()
    #unique_res = list()
    if logging:
        log_worker(all_results, res, category)
        #print(type(res))
        #print(res)
    if output_type == 'str':
        return str(res)
    else:
        return res

def execute_pipe_worker(all_results: dict, command: str, category: str, exact_time, stdin_data='', stdout_file='', no_last_line=True) -> list[str]:
    try:
        if stdin_data == '':
            if exact_time == 0:
                res = subprocess.run(command, capture_output=True)
            else:
                res = subprocess.run(command, timeout=exact_time, capture_output=True)
        else:
            if exact_time == 0:
                res = subprocess.run(command, capture_output=True, text=True, input=stdin_data)
            else:
                res = subprocess.run(command, timeout=exact_time, capture_output=True, text=True, input=stdin_data)
        #print(res)
        res = res.stdout.splitlines()
        log_worker(all_results, res, category)
        return res
    except subprocess.TimeoutExpired as e:
        res = e.stdout.splitlines()
        log_worker(all_results, res, category)
        if stdout_file != '':
            with open(stdout_file, 'w') as f:
                f.writelines(res)
        if no_last_line:
            return res[:-1]
        else:
            return res

def get_column(text, number=0) -> list:
    #print('!!!!!!!!!!!!!!!!!!!!!')
    ret = []
    if isinstance(text, str):
        for line in text:
            #print(line)
            ret.append(line.split()[number])
    elif isinstance(text, list):
        #print('##')
        for item in text:
            ret.append(str(item).split()[number])
    else:
        print('Error')
        print(type(text))
    return ret

def get_csv_column(res_file: str, column_name: str):
    res_columns = defaultdict(list)
    with open(res_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            for (k,v) in row.items():
                res_columns[k].append(v)
    return res_columns[column_name]

def nmap_services_scan(all_results: dict, host_and_ports: list) -> list:
    nmap_service_scan_input = dict()
    for item in host_and_ports:
        host, port = item.split(':')
        if host not in nmap_service_scan_input.keys():
            nmap_service_scan_input[host] = [int(port)]
        else:
            nmap_service_scan_input[host].append(int(port))
    for k in sorted(nmap_service_scan_input):
        nmap_service_scan_input[k] = sorted(nmap_service_scan_input[k])
    all_results['SERVICES_PORTS'] = nmap_service_scan_input

    res_with_timestamps = []
    for k, v in all_results['SERVICES_PORTS'].items():
        ports_list = ""
        for i in range(0, len(v)):
            if i != len(v) - 1:
                ports_list += str(v[i]) + ','
            else:
                ports_list += str(v[i])
        timestamp = foldername[0] + os.sep + 'nmap_results' + os.sep + datetime.now().strftime('%d-%m-%Y-%H%M%S') + '.txt'
        command = 'nmap -oX ' + timestamp + ' -sV -n -Pn -p' + ports_list + ' --max-parallelism 900 --unprivileged ' + k
        execute_worker(all_results, command, 'RANDOM', no_stdout=True, logging=False)
        #print(command)
        res_with_timestamps.append(timestamp)
    return res_with_timestamps

def scan_list_converting(input: list) -> (list, list):
    cpe_list = []
    service_further_scan_list = []
    for service in input:
        ip, port, transport, opened_status, protocol, product, tunnel = service.split(',')
        cpe_list.append((ip, port, product))
        service_further_scan_list.append((ip, port, protocol, tunnel))
    return cpe_list, service_further_scan_list


def nmap_results_for_cve_list(nmap_xmls: list) -> list:
    services = []
    for resfile in nmap_xmls:
        nmap_report = NmapParser.parse_fromfile(resfile)
        #print(nmap_report)
        for h in nmap_report.hosts:
            print(h)
            for s in h.services:
                print(s)
                if s.state != "open|filtered":
                    services.append(str(h.ipv4) + "," + str(s.port) + "," + str(s.protocol) + "," + str(s.state) + "," + str(
                    s.service) + "," + str(s.banner)+ "," + str(s.tunnel))
    return services

def parse_to_cpe(services_list: list) -> list:
    print(services_list)
    services = []
    for service in services_list:
        print(service[2][9:])
        #execute_worker('','cpe2cve')
        services.append((service[0], service[1], service[2]))
    return services

def links_ip_to_dns(dnsx_output: list) -> dict:
    ip_to_dns = dict()
    for line in dnsx_output:
        dns, ip = line.split()
        ip = ip[1:-1]
        if ip not in ip_to_dns.keys():
            ip_to_dns[ip] = [dns]
        else:
            ip_to_dns[ip].append(dns)
    return ip_to_dns

def extract_from_urls():
    os.listdir()

# def unfurl_urls(all_results, urls, scheme, dns, port):
#     extract_from_urls(scheme, dns, port)
#     site_external_urls = []
#     fname = foldername[0] + os.sep + 'url_results' + os.sep + scheme + '-' +dns + '-' + port + '.txt'
#     print(fname)
#     site_inner_urls = execute_worker(all_results, 'grep {0}://{1} {2}'.format(scheme, dns, fname), fname)
#     print(site_inner_urls)
#     write_to_file(foldername[0] + os.sep + 'url_prep_results' + os.sep, scheme + '-' +dns + '-' + port + '_inner.txt', site_inner_urls)
#     #execute_pipe_worker(urls) #
#     site_all_domains = []
#     site_all_dynamic_urls = []
#     return []

#def
#    foldername[0] + os.sep + 'ffuf_results' + os.sep + addr + '-' + port + '.csv'

def web_extracting(all_results: dict) -> (list, list):
    url_files_folder = foldername[0] + os.sep + 'url_results'
    url_prep_files_folder = foldername[0] + os.sep + 'url_prep_results'
    url_files = os.listdir(url_files_folder)
    site_inner_urls_all = []
    site_outer_urls_all = []
    for f in url_files:
        scheme, host, port = f[:-4].split('-')
        site_all_urls_file = open(url_files_folder + os.sep + f, 'r')
        site_all_urls = site_all_urls_file.readlines()
        site_all_urls_file.close()
        site_inner_urls = execute_worker(all_results,
                                             'grep -oE \"(http|https)://(.*){0}(.*)\" {1}'.format(host, url_files_folder + os.sep + f), f)
        site_outer_urls_all.extend([i for i in site_all_urls if i not in site_inner_urls])
        site_inner_urls_all.extend(site_inner_urls)
        #print(site_inner_urls)
        #print("-"*50)
    print(site_inner_urls_all)
    site_inner_urls_all.extend(filter_list(target_domain[0], site_outer_urls_all))
    site_inner_urls_all = uniq_and_sort(site_inner_urls_all)
    print(site_inner_urls_all)
    write_to_file(url_prep_files_folder, 'inner_urls.txt', site_inner_urls_all)
    write_to_file(url_prep_files_folder, 'outer_urls.txt', site_outer_urls_all)
    return site_inner_urls_all, site_outer_urls_all

def web_init_recon(all_results: dict, scheme: str, hosts: list, proxy=False):
    already_scanned = []
    for host in hosts:
        if host not in already_scanned:
            web_recon(all_results, scheme, host[0], host[1], proxy)
            #web_discovering(all_results, scheme, host[0], host[1])
            already_scanned.append(host)
            for dns in all_results['DNS_IP'][host[0]]:
                if (dns, host[1]) not in already_scanned:
                    #urls = web_discovering(all_results, scheme, dns, host[1])
                    web_recon(all_results, scheme, dns, host[1], proxy)
                    already_scanned.append((dns, host[1]))
                    #important_urls = declutter_urls(all_results, urls)
                    #print('important_urls')
                    #print(important_urls)

def web_recon(all_results: dict, scheme: str, host: str, port: str, proxy=False):
    urls = web_discovering(all_results, scheme, host, port, proxy)
    print('urls')
    print(len(urls))
    #print(urls[:5])

    with open(foldername[0] + os.sep + 'url_results' + os.sep + scheme + '-' + host + '-' + port + '.txt', 'w') as f:
        f.writelines(line+'\n' for line in urls)
    headless_recon(all_results, scheme, host, port, proxy)
    web_intrude(all_results, scheme, host, port, proxy)
    #unfurled = unfurl_urls(all_results, urls, scheme, dns, port)
    #target_urls, param_list = unfurl_urls(all_results, urls)
    #web_fuzz(all_results, urls)

def web_discovering(all_results: dict, scheme: str, addr: str, port: str, proxy1=False) -> list:
    proxy=False
    urls = []
    ffuf_file_direnum = foldername[0] + os.sep + 'ffuf_results' + os.sep + addr + '-' + port + '.csv'
    hakrawler_file = foldername[0] + os.sep + 'hakrawler_results' + os.sep + addr + '-' + port + '.txt'
    if proxy == False:
        execute_worker(all_results,
                       'ffuf -H \"' + user_agent + '\" -u ' + scheme + '://' + addr + ':' + port + '/FUZZ -w !assets\\wordlist.txt -ac -mc 100,101,102,103,200,201,202,203,204,205,206,207,208,301,302,303,307,401,403,405,406,407,408,409,410,411,417,500,501,502 -of csv -o ' + ffuf_file_direnum,
                       'ffuf_direnum')
        ffuf_urls = get_csv_column(ffuf_file_direnum, 'url')
        hakrawler_res = execute_pipe_worker(all_results,
                                            'hakrawler -d 3 -subs -s -u -insecure -h \"{0}\"'.format(user_agent),
                                            'hakrawler', 5, """{}""".format('\n'.join(ffuf_urls)), hakrawler_file)
    else:
        execute_worker(all_results, 'ffuf -H \"'+user_agent+'\" -u '+scheme+'://' + addr + ':' + port + '/FUZZ -w !assets\\wordlist.txt -ac -mc 100,101,102,103,200,201,202,203,204,205,206,207,208,301,302,303,307,401,403,405,406,407,408,409,410,411,417,500,501,502 -of csv -o '+ffuf_file_direnum+' -x '+proxy, 'ffuf_direnum')
        ffuf_urls = get_csv_column(ffuf_file_direnum, 'url')
        hakrawler_res = execute_pipe_worker(all_results, 'hakrawler -d 3 -subs -s -u -insecure -h \"{0}\" --proxy {1}'.format(user_agent, proxy), 'hakrawler', 120, """{}""".format('\n'.join(ffuf_urls)), hakrawler_file)

    #cariddi_file = foldername[0] + os.sep + 'cariddi_results' + os.sep + addr + '-' + port + '.txt'
    #execute_worker(all_results, 'cariddi -e -err -ext 1 -intensive -s -info -ua \"{0}\"'.format(user_agent), 'cariddi', stdin_data=hakrawler_file, stdout_file=cariddi_file)
    hakrawler_urls = get_column(hakrawler_res, 1)
    urls.extend(ffuf_urls)
    urls.extend(hakrawler_urls)

    with open(hakrawler_file+'_', 'w') as f:
        f.writelines(line+'\n' for line in hakrawler_urls)

    urls = list(set(urls))
    log_intermediate('Number of urls: '+str(len(urls)))
    log_intermediate(scheme + '://'+addr+':'+port)
    #log_intermediate(uniq_urls)
    return urls

def headless_recon(all_results: dict, scheme: str, host: str, port: str, proxy=False):
    katana_file_direnum = foldername[0] + os.sep + 'katana_results' + os.sep + host + '-' + port + '.txt'
    if proxy:
        execute_pipe_worker(all_results, "katana -jc -aff -fx -iqp -hl -xhr -silent -d 4 -u {0}://{1}:{2} -proxy {3} -o {4}".format(scheme, host, port, proxy, katana_file_direnum), "katana", 480)
    else:
        execute_pipe_worker(all_results, "katana -jc -aff -fx -iqp -hl -xhr -silent -d 4 -u {0}://{1}:{2} -o {3}".format(scheme, host, port, katana_file_direnum), "katana", 480)

#def declutter_urls(all_results, urls):
#    return execute_pipe_worker(all_results, 'godeclutter', 'godeclutter', 1200, """{}""".format('\n'.join(urls)), foldername[0] + os.sep + 'urls_'+gen_timestamp()+'.txt', False)

def web_intrude(all_results: dict, scheme: str, host: str, port: str, proxy=False):
    dalfox_file_direnum = foldername[0] + os.sep + 'dalfox_results' + os.sep + host + '-' + port + '.txt'
    if proxy:
        execute_worker(all_results, 'dalfox file -b --deep-domxss {0}://{1}:{2} -proxy {3} -o {4}'.format(scheme, host, port, proxy, dalfox_file_direnum), 'dalfox')
    else:
        execute_worker(all_results, 'dalfox file -b --deep-domxss {0}://{1}:{2} -o {3}'.format(scheme, host, port, proxy, dalfox_file_direnum), 'dalfox')

#def web_fuzz(all_resuls: dict):
#    execute_worker(all_resuls, '', '')