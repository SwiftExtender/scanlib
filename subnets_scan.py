import os
import sys
import subprocess
from datetime import datetime
import html_logger

ctime_str = datetime.now().strftime('%d-%m-%Y-%H%M%S')
print("Current working directory: {0}".format(os.getcwd()))
foldername = 'scan_results' + os.sep + ctime_str+'-results_net'
print(foldername)
os.makedirs(foldername)
os.makedirs(foldername+os.sep+'nmap_results')
all_results = {}
#logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',datefmt='%Y-%m-%d %H:%M:%S',level=logging.INFO, filename=foldername+os.sep+'log.txt')
html_logger.setup('Netscan results', filename=foldername+os.sep+'results.html', version="0.0.1")
all_results = dict()

def gen_timestamp():
    return datetime.now().strftime('%d %H:%M:%S')

def execute_worker(command, category, lower_flag=True, stdin_data = [], output_type='list', no_stdout = False, wait=True, logging=True):
    if no_stdout:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL)
        if wait:
            proc.communicate()
        return True #ignore stdout operations, fix later
    else:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE)
    if stdin_data != []:
        #print('stdin_data')
        #print(stdin_data)
        if lower_flag:
            res = proc.communicate(input=bytes("{}".format("\n".join(stdin_data)), encoding ='ascii'))[0].decode(encoding ='ascii').lower().splitlines()
            #print('res')
            #print(res)
        else:
            res = proc.communicate(input=bytes("{}".format("\n".join(stdin_data)), encoding ='ascii'))[0].decode(encoding ='ascii').splitlines()
    else:
        if lower_flag:
            res = proc.communicate()[0].decode(encoding='ascii').lower().splitlines()
        else:
            res = proc.communicate()[0].decode(encoding ='ascii').splitlines()
    #unique_res = list()
    if logging:
        html_logger.dbg(gen_timestamp())
        html_logger.dbg('----'+category+'----')
        html_logger.dbg('Count of values: '+str(len(res)))
        unique_res = list(set(res))
        html_logger.dbg('Unique values: '+str(len(unique_res)))
        for item in unique_res:
            html_logger.info(item)
        if category in all_results.keys():
            for item in unique_res:
                all_results[category].append(item)
        else:
            all_results[category] = unique_res
    if output_type == 'str':
        return str(res)
    else:
        return res


ips = open('n.txt','r')
smap_input = ips.readlines()
print(smap_input)
ips.close()
execute_worker('smap -p80,443,8000,8080,8443,8800,8843 -iL - -oP res.txt', 'PORTS', smap_input)
print(all_results['PORTS'])