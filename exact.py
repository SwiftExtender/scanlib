from scanlib import *
import os
all_results = {}
text = list()
if type(text) == 'list':
    print(11)
else:
    print(22)
#print(type(list(text)))
#ffuf_urls = ['abc', 'bce']
#print("""{}""".format(os.linesep.join(ffuf_urls)))

#print(create_artifacts('addr-port'))
#hakrawler_file = foldername[0] + os.sep + 'hakrawler_results' + os.sep + '123-.txt'
#ffuf_urls='https://zagony.ru'
#execute_worker(all_results, 'hakrawler -d 3 -subs -s -u -insecure -h \"{0}\"'.format(user_agent), 'hakrawler', stdin_data=ffuf_urls, stdout_file=hakrawler_file, exact_time=5)
#res = execute_pipe_worker(all_results, 'hakrawler -d 3 -subs -s -u -insecure -h \"{0}\"'.format(user_agent), 'hakrawler', 5, ffuf_urls, hakrawler_file)
#print(get_column(res, 1))
#print('###')
#print(get_column(res[:-1], 1))