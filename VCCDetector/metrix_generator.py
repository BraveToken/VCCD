from matcher import *
import difflib
import time
import common


def match(source_list, VFList):
    matched_list = []
    # missed_list = []
    # thresholds = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    thresholds = [0.8]
    for threshold in thresholds:
        TP = 0.
        FP = 0.
        TN = 0.
        FN = 0.
        UNK = 0
        start_time = time.time()
        for source in source_list:
            matched = ''
            label = ''
            num = 0
            for vf in VFList:
                len_matched_c = calComLen(source.source_lines, vf.context)
                # len_matched_c = LCS(source.source_lines, vf.context)
                matched_del = iscontain(source.source_lines, vf.del_lines)
                len_matched_hunk = 0
                for hunk in vf.add_lines:
                    if KMP_algorithm(source.source_lines, hunk):
                        len_matched_hunk += 1
                try:
                    ratio = float(len_matched_c)/len(vf.context)
                except ZeroDivisionError as err:
                    # print('ZeroDivisionError: {e}'.format(e=err))
                    # print(vf.path)
                    ratio = 1
                # print(ratio)
                if(ratio >= threshold and matched_del and len_matched_hunk == 0):
                    matched = vf.cve+vf.filename
                    num += 1
                    if source.cve == vf.cve and '_before_' in source.path:
                        TP += 1
                        label = 'TP'
                        matched_list.append(common.MatchInfo(
                            source.path, num, matched, label))
                        break
                    elif source.cve == vf.cve and '_after_' in source.path:
                        FP += 1
                        label = 'FP'
                        matched_list.append(common.MatchInfo(
                            source.path, num, matched, label))
                        break
                    # elif source.filename == vf.filename and source.time <= vf.time:
                    #     TP += 1
                    #     label = 'TP'
                    #     matched_list.append(common.MatchInfo(
                    #         source.path, num, matched, label))
                    #     break
                    # else:
                    #     UNK += 1
                    #     label = 'UNK'
                    #     matched_list.append(common.MatchInfo(
                    #         source.path, num, matched, label))
                    #     break

            if num == 0:
                # matched_list.append(common.MatchInfo(
                #     source.filename, num, matched, TP, FP))
                if '_before_' in source.path:
                    FN += 1
                    label = 'FN'
                    # missed_list.append(source.filename)
                else:
                    TN += 1
                    label = 'TN'
                matched_list.append(common.MatchInfo(
                    source.path, num, matched, label))
        # with open('missed.txt', 'w') as f:
        #     f.write('\n'.join(missed_list))
        P = TP/(TP+FP)
        R = TP/(TP+FN)
        A = (TP+TN)/(TP+FP+TN+FN)
        F1 = 2*(P*R)/(P+R)
        print("threshold:", threshold)
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
        print('[+] time cost of matching: %.3f' % elapsed_time)
    return matched_list


def mult_match(source_list, VFList, manual_labels):
    # matched_list = []
    # missed_list = []
    thresholds = [0.8]
    # thresholds = [0.4]
    for threshold in thresholds:
        TP = 0.
        FP = 0.
        TN = 0.
        FN = 0.
        UNK = 0
        match_result_set = set()
        start_time = time.time()
        for source in source_list:
            matched = ''
            label = ''
            num = 0
            # cve_id_s = '_'.join(source[0].split('_')[0:-1])
            for vf in VFList:
                matched_del = iscontain(source.source_lines, vf.del_lines)
                if matched_del:
                    len_matched_hunk = 0
                    for hunk in vf.add_lines:
                        if KMP_algorithm(source.source_lines, hunk):
                            len_matched_hunk += 1
                    if len_matched_hunk == 0:
                        len_matched_c = calComLen(
                            source.source_lines, vf.context)
                        # print('mactced_c: %d matched_del: %d matched_add: %d' %
                        #       (matched_c, matched_del, matched_add))
                        # print('length of context: %d, length of del: %d, length of add: %d' % (
                        #     len(vf.context), len(vf.del_lines), len(vf.add_lines)))
                        try:
                            ratio = float(len_matched_c)/len(vf.context)
                        except ZeroDivisionError as err:
                            # print('ZeroDivisionError: {e}'.format(e=err))
                            # print(vf.path)
                            ratio = 1
                        if ratio >= threshold:
                            # if(matched_del and len_matched_c == len(vf.context) and len_matched_hunk == 0):
                            matched = vf.cve+'_'+str(vf.time)+'_'+vf.filename
                            num += 1
                            # cve_id_v = '.'.join(vf.filename.split('.')[0:-1])
                            # if cve_id_s == cve_id_v:
                            if source.cve == vf.cve and '_before_' in source.path:
                                TP += 1
                                label = 'TP'
                            elif source.cve == vf.cve and '_after_' in source.path:
                                FP += 1
                                label = 'FP'
                            elif source.filename == vf.filename and source.time <= vf.time:
                                TP += 1
                                label = 'TP'
                            elif source.filename == vf.filename and source.time > vf.time:
                                FP += 1
                                label = 'FP'
                            else:
                                # check in manual labels
                                found = False
                                for label in manual_labels:
                                    label_split = label.rstrip('\n').split(' ')
                                    if label_split[1] == vf.cve and label_split[2] in source.path:
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
                            match_result_set.add(common.MatchInfo(
                                source.path, matched, label))

            if num == 0:
                # matched_list.append(common.MatchInfo(
                #     source.filename, num, matched, TP, FP))
                if '_before_' in source.path:
                    FN += 1
                    label = 'FN'
                    # missed_list.append(source.filename)
                else:
                    TN += 1
                    label = 'TN'
                match_result_set.add(common.MatchInfo(
                    source.path, matched, label))
        # with open('missed.txt', 'w') as f:
        #     f.write('\n'.join(missed_list))
        P = TP/(TP+FP)
        R = TP/(TP+FN)
        A = (TP+TN)/(TP+FP+TN+FN)
        F1 = 2*(P*R)/(P+R)
        print("threshold:", threshold)
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
