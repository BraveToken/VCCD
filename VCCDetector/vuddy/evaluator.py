import re
import time
import subprocess
from collections import namedtuple
from result_printer import *
MatchInfo = namedtuple('MatchInfo', ['source_name', 'vul_list', 'label'])


def preprocess(vuln_funcs, target_funcs, abstract_switch):
    start_time = time.time()
    # subprocess.Popen(
    #     'hmark_4.0.1_win_x64.exe -n -c {} OFF'.format(vuln_funcs), shell=True)
    os.system(
        'hmark_4.0.1_win_x64.exe -n -c {0} {1}'.format(vuln_funcs, abstract_switch))
    elapsed_time = time.time()-start_time
    print('[+] Generating Vulnerability Fingerprint ... %.1f' % elapsed_time)
    start_time = time.time()
    # subprocess.Popen(
    #     'hmark_4.0.1_win_x64.exe -n -c {} OFF'.format(target_funcs), shell=True)
    os.system(
        'hmark_4.0.1_win_x64.exe -n -c {0} {1}'.format(target_funcs, abstract_switch))
    elapsed_time = time.time()-start_time
    print('[+] Generating Target Code Fingerprint ... %.1f' % elapsed_time)


def divider(filename):
    # filename = 'hashmark_0_CVE-2016-10154.hidx'
    file_dict_list = []
    with open(filename, 'r') as fp:
        raw_info = fp.readlines()[1]
    func_list = re.findall("file': '(.*?)', 'function id", raw_info)
    length_list = re.findall(
        "function length': '(.*?)', 'hash value", raw_info)
    hash_list = re.findall("hash value': '(.*?)'}", raw_info)
    key_list = ['file', 'length', 'hash']
    for i in range(len(func_list)):
        file_tuple = zip(
            key_list, [func_list[i], length_list[i], hash_list[i]])
        file_dict_list.append(dict(file_tuple))
    return file_dict_list


def evaluate(target_dict_list, vul_dict_list, manual_labels):
    TP = 0.
    FP = 0.
    TN = 0.
    FN = 0.
    UNK = 0
    match_result_set = set()
    start_time = time.time()
    for target in target_dict_list:
        # clone_type = t_title = re.split('/|\\\\', target['file'])[-2]
        # if clone_type == 'Type-1':
        #     continue
        matched = ''
        label = ''
        num = 0
        t_title = re.split('/|\\\\', target['file'])[-1]
        t_cve = t_title.split('_')[0]
        t_time = int(t_title.split('_')[3])
        t_name = '_'.join(t_title.split('_')[4:])
        for vuln in vul_dict_list:
            if target['length'] == vuln['length'] and target['hash'] == vuln['hash']:
                p_cve = vuln['file'].split('_')[1]
                p_time = int(vuln['file'].split('_')[2])
                p_name = '_'.join(vuln['file'].split('_')[
                    3:]).replace('_OLD.c', '.c')
                p_info = p_cve+'_'+str(p_time)+'_'+p_name
                num += 1
                if t_cve == p_cve and '_before_' in t_title:
                    TP += 1
                    label = 'TP'
                elif t_cve == p_cve and '_after_' in t_title:
                    FP += 1
                    label = 'FP'
                elif t_name == p_name and t_time <= p_time:
                    TP += 1
                    label = 'TP'
                elif t_name == p_name and t_time > p_time:
                    FP += 1
                    label = 'FP'
                else:
                    # check in manual labels
                    found = False
                    for label in manual_labels:
                        label_split = label.rstrip('\n').split(' ')
                        if label_split[1] == p_cve and label_split[2] in vuln['file']:
                            if label_split[0] == 'TP':
                                TP += 1
                                label = 'TP'
                            else:
                                FP += 1
                                label = 'FP'
                            found = True
                            break
                    if not found:
                        UNK += 1
                        label = 'UNK'
                match_result_set.add(MatchInfo(target['file'], p_info, label))
        if num == 0:
            if '_before_' in t_title:
                FN += 1
                label = 'FN'
            else:
                TN += 1
                label = 'TN'
            match_result_set.add(MatchInfo(target['file'], '', label))
    P = TP/(TP+FP)
    R = TP/(TP+FN)
    A = (TP+TN)/(TP+FP+TN+FN)
    F1 = 2*(P*R)/(P+R)
    print("Train Score:")
    print("TP\tFP\tTN\tFN\tUNK\tP\tR\tA\tF1")
    print("%d\t%d\t%d\t%d\t%d\t%.4f\t%.4f\t%.4f\t%.4f" %
          (TP, FP, TN, FN, UNK, P, R, A, F1))
    print("Worst Case:")
    P = TP/(TP+FP + UNK)
    R = TP/(TP+FN)
    A = (TP+TN)/(TP+FP+TN+FN+UNK)
    F1 = 2*(P*R)/(P+R)
    print("%.4f\t%.4f\t%.4f\t%.4f" % (P, R, A, F1))
    print("Best Case:")
    P = (TP+UNK)/(TP+FP+UNK)
    R = (TP+UNK)/(TP+UNK+FN)
    A = (TP+TN+UNK)/(TP+FP+TN+FN+UNK)
    F1 = 2*(P*R)/(P+R)
    print("%.4f\t%.4f\t%.4f\t%.4f" % (P, R, A, F1))
    print('---------------------------------------------------------')

    elapsed_time = time.time()-start_time
    print('[+] time cost of mult_matching: %.3f' % elapsed_time)
    return match_result_set


if __name__ == '__main__':
    vuln_funcs = 'vuln'
    target_funcs = 'totalClone'
    abstract_switch = 'OFF'
    preprocess(vuln_funcs, target_funcs, abstract_switch)
    vul_hidx = 'hidx\\hashmark_0_vuln.hidx'
    target_hidx = 'hidx\\hashmark_0_totalClone.hidx'
    vul_dict_list = divider(vul_hidx)
    target_dict_list = divider(target_hidx)
    with open('manual.txt', 'r') as fp:
        manual_labels = fp.readlines()
    match_result_set = evaluate(target_dict_list, vul_dict_list, manual_labels)
    with open('vuddy_abstract_result.txt', 'w') as fp:
        for match in match_result_set:
            fp.write(match.source_name.split('/')
                     [-1]+' '+match.vul_list+' '+match.label+'\n')
    printToXlsx(match_result_set)
    # total_name_set = {target['file'] for target in target_dict_list}
    # matched_name_set = set()
