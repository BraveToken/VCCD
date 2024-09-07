# reporter.py
#   Reporter class
#
# Jiyong Jang, 2012
#
import time
from collections import defaultdict
import common
import re
from result_printer import *
import patchloader
import sourceloader


class Reporter(object):

    def __init__(self, patch, source):
        self._patch_list = list(patch.items())
        self._npatch = patch.length()
        self._source_list = list(source.items())
        self._nsource = source.length()
        self._match_dict = source.match_items()
        self._second_match_dict = source.second_match_items()
        self._context_dict = defaultdict(list)
        self._exact_dict = defaultdict(list)
        self._source_names = source.name_items()

    def _exact_match(self):
        '''
        Exact-matching test to catch Bloom filters errors
        '''
        print('[+] performing an exact matching test')
        start_time = time.time()
        exact_nmatch = 0

        for patch_id, source_id_list in list(self._match_dict.items()):
            patch_norm_lines = self._patch_list[patch_id].norm_lines
            patch_norm_length = len(patch_norm_lines)
            for source_id in source_id_list:
                source_norm_lines = self._source_list[source_id].norm_lines
                source_norm_length = len(source_norm_lines)

                for i in range(0, (source_norm_length-patch_norm_length+1)):
                    patch_line = 0
                    source_line = i
                    while patch_norm_lines[patch_line] == source_norm_lines[source_line]:
                        patch_line += 1
                        source_line += 1

                        if patch_line == patch_norm_length:
                            common.verbose_print('  [-] exact match - %s : %s (line #%d)' % (
                                self._patch_list[patch_id].file_path, self._source_list[source_id].file_path, i+1))
                            self._context_dict[patch_id].append(common.ContextInfo(source_id, max(
                                0, i-common.context_line), i, source_line, min(source_line+common.context_line, source_norm_length-1)))
                            exact_nmatch += 1
                            break

                        # while source_norm_lines[source_line] == '':
                        #     source_line += 1

                        while source_line < source_norm_length-patch_norm_length and source_norm_lines[source_line] == '':
                            source_line += 1

                        if source_line == source_norm_length-patch_norm_length:
                            break

        elapsed_time = time.time() - start_time
        print('[+] %d exact matches ... %.1fs\n' %
              (exact_nmatch, elapsed_time))
        return exact_nmatch

    def _second_exact_match(self):
        '''
        Exact-matching test to catch Bloom filters errors
        '''
        print('[+] performing an exact matching test')
        start_time = time.time()
        exact_nmatch = 0

        for source_id, patch_id_list in list(self._second_match_dict.items()):
            source_norm_lines = self._source_list[source_id].norm_lines
            source_norm_length = len(source_norm_lines)
            for patch_id in patch_id_list:
                patch_norm_lines = self._patch_list[patch_id].norm_lines
                patch_norm_length = len(patch_norm_lines)

                for i in range(0, (source_norm_length-patch_norm_length+1)):
                    patch_line = 0
                    source_line = i
                    while patch_norm_lines[patch_line] == source_norm_lines[source_line]:
                        patch_line += 1
                        source_line += 1

                        if patch_line == patch_norm_length:
                            common.verbose_print('  [-] exact match - %s : %s (line #%d)' % (
                                self._patch_list[patch_id].file_path, self._source_list[source_id].file_path, i+1))
                            self._exact_dict[source_id].append(common.MatchedPatch(
                                patch_id, self._patch_list[patch_id].orig_lines))
                            exact_nmatch += 1
                            break

                        while source_line < source_norm_length-patch_norm_length and source_norm_lines[source_line] == '':
                            source_line += 1

                        if source_line == source_norm_length-patch_norm_length:
                            break

        elapsed_time = time.time() - start_time
        print('[+] %d exact matches ... %.1fs\n' %
              (exact_nmatch, elapsed_time))
        return exact_nmatch

    def _html_escape(self, string):
        '''
        Escape HTML
        '''
        return ''.join(common.html_escape_dict.get(c, c) for c in string)

    def evaluate(self, manual_labels):
        TP = 0.
        FP = 0.
        TN = 0.
        FN = 0.
        UNK = 0
        matched_set = set()
        match_result_set = set()
        match_TP_set = set()
        match_FP_set = set()
        match_TN_set = set()
        match_FN_set = set()
        match_UNK_set = set()
        # exact_nmatch = self._exact_match()
        start_time = time.time()

        for patch_id, context_list in list(self._context_dict.items()):
            p = self._patch_list[patch_id]
            p_cve = p.file_path.split('_')[1]
            p_time = int(p.file_path.split('_')[2])
            p_name = p.file_path.split(' ')[-2].replace('_OLD', '')
            p_info = p_cve+'_'+str(p_time)+'_'+p_name
            for context in context_list:
                s = self._source_list[context.source_id]
                s_title = re.split('/|\\\\', s.file_path)[-1]
                matched_set.add(s.file_path)
                s_cve = s_title.split('_')[0]
                s_time = int(s_title.split('_')[3])
                s_name = '_'.join(s_title.split('_')[4:])
                if p_cve == s_cve and '_before_' in s_title:
                    # TP += 1
                    label = 'TP'
                    match_TP_set.add(
                        common.MatchInfo(s.file_path, p_info, label))
                elif p_cve == s_cve and '_after_' in s_title:
                    # FP += 1
                    label = 'FP'
                    match_FP_set.add(
                        common.MatchInfo(s.file_path, p_info, label))
                elif p_name == s_name and p_time >= s_time:
                    # TP += 1
                    label = 'TP'
                    match_TP_set.add(
                        common.MatchInfo(s.file_path, p_info, label))
                elif p_name == s_name and p_time < s_time:
                    # FP += 1
                    label = 'FP'
                    match_FP_set.add(
                        common.MatchInfo(s.file_path, p_info, label))
                else:
                    # check in manual labels
                    found = False
                    for label in manual_labels:
                        label_split = label.rstrip('\n').split(' ')
                        if label_split[1] == p_cve and label_split[2] == s_title:
                            if label_split[0] == 'TP':
                                # TP += 1
                                label = 'TP'
                                match_TP_set.add(
                                    common.MatchInfo(s.file_path, p_info, label))
                            else:
                                # FP += 1
                                label = 'FP'
                                match_FP_set.add(
                                    common.MatchInfo(s.file_path, p_info, label))
                            found = True
                            break
                    if not found:
                        UNK += 1
                        label = 'UNK'
                        match_UNK_set.add(
                            common.MatchInfo(s.file_path, p_info, label))
                match_result_set.add(
                    common.MatchInfo(s.file_path, p_info, label))
        print('matched number:', len(matched_set))
        # for match in match_TP_set:
        #     if match.label == 'TP':
        #         match
        print(len(self._source_names))
        unmatched_set = self._source_names-matched_set
        for source_path in unmatched_set:
            if '_after_' in source_path:
                TN += 1
                label = 'TN'
            else:
                FN += 1
                label = 'FN'
            match_result_set.add(
                common.MatchInfo(source_path, '', label))

        TP = len(match_TP_set)
        FP = len(match_FP_set)
        UNK = len(match_UNK_set)
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
        print('[+] time cost of matching ... %.1fs\n' % elapsed_time)
        return match_result_set

    def further_evaluate(self):
        TP = 0.
        FP = 0.
        TN = 0.
        FN = 0.
        UNK = 0
        matched_set = set()
        match_result_set = set()
        # exact_nmatch = self._exact_match()
        start_time = time.time()

        for source_id, patch_list in list(self._exact_dict.items()):
            s = self._source_list[source_id]
            s_title = re.split('/|\\\\', s.file_path)[-1]
            matched_set.add(s_title)
            s_cve = s_title.split('_')[0]
            s_time = int(s_title.split('_')[3])
            s_name = '_'.join(s_title.split('_')[4:])

            for patch in patch_list:
                p = self._patch_list[patch.patch_id]
                p_cve = p.file_path.split('_')[1]
                p_time = int(p.file_path.split('_')[2])
                p_name = p.file_path.split(' ')[-2].replace('_OLD', '')
                p_info = p_cve+'_'+str(p_time)+p_name
                if p_cve == s_cve and '_before_' in s_title:
                    TP += 1
                    label = 'TP'
                    break
                elif p_cve == s_cve and '_after_' in s_title:
                    FP += 1
                    label = 'FP'
                    break
                # elif p_name == s_name and p_time >= s_time:
                #     TP += 1
                #     break
                # else:
                #     UNK += 1
                #     break
                match_result_set.update(
                    common.MatchInfo(s.file_path), p_info, label)
        print('matched number:', len(matched_set))
        unmatched_set = self._source_names-matched_set
        for source_name in unmatched_set:
            if '_after_' in source_name:
                TN += 1
                label = 'TN'
            else:
                FN += 1
                label = 'FN'
            match_result_set.update(
                common.MatchInfo(s.file_path), p_info, label)
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
        print('[+] time cost of further matching ... %.1fs\n' % elapsed_time)
        return match_result_set

    def output(self, outfile='output.html'):
        '''
        Perform an exact matching test and generate a report
        '''
        exact_nmatch = self._exact_match()
        if exact_nmatch == 0:
            return exact_nmatch

        with open('manual.txt', 'r') as fp:
            manual_labels = fp.readlines()
        match_result_set = self.evaluate(manual_labels)
        with open('redebug_mod.txt', 'w') as fp:
            for match in match_result_set:
                fp.write(match.source_name.split('\\')
                         [-1]+' '+match.vul_list+' '+match.label+'\n')
        printToXlsx(match_result_set)
        # second_exact_match = self._second_exact_match()
        # self.further_evaluate()

        print('[+] generating a report')
        start_time = time.time()

        out = open(outfile, 'w')
        # html head - css, javascript
        out.write("""
<!DOCTYPE html>
<html>
<head>
    <title>ReDeBug - Report</title>
    <style type="text/css">
    .container { padding: 3px 3px 3px 3px; font-size: 14px; }
    .patch { background-color: #CCCCCC; border: 2px solid #555555; margin: 0px 0px 5px 0px }
    .source { background-color: #DDDDDD; padding: 3px 3px 3px 3px; margin: 0px 0px 5px 0px }
    .filepath { font-size: small; font-weight: bold; color: #0000AA; padding: 5px 5px 5px 5px; }
    .codechunk { font-family: monospace; font-size: small; white-space: pre-wrap; padding: 0px 0px 0px 50px; }
    .linenumber { font-family: monospace; font-size: small; float: left; color: #777777; }
    </style>
    <script language="javascript">
        function togglePrev(node) {
            var targetDiv = node.previousSibling;
            targetDiv.style.display = (targetDiv.style.display=='none')?'block':'none';
            node.innerHTML = (node.innerHTML=='+ show +')?'- hide -':'+ show +';
        }
        function toggleNext(node) {
            var targetDiv = node.nextSibling;
            targetDiv.style.display = (targetDiv.style.display=='none')?'block':'none';
            node.innerHTML = (node.innerHTML=='+ show +')?'- hide -':'+ show +';
        }
    </script>
</head>
<body>
<div style="width: 100%; margin: 0px auto">""")
        # unpatched code clones
        out.write("""
    <b># <i>unpatched code clones:</i> <font style="color:red">%d</font></b>""" % exact_nmatch)

        for patch_id, context_list in list(self._context_dict.items()):
            p = self._patch_list[patch_id]
            out.write("""
    <div class="container">
        <br />""")
            # patch info
            out.write("""
        <div class="patch">
            <div class="filepath">%s</div>
            <div class="codechunk">%s</div>
        </div>""" % (p.file_path, p.orig_lines))

            for context in context_list:
                s = self._source_list[context.source_id]
                # source info - prev_context
                out.write("""
        <div class="source">
            <div class="filepath">%s</div>
            <div style="display: none">
                <div class="linenumber">""" % s.file_path)

                for i in range(context.prev_context_line, context.start_line):
                    out.write("""
                %d<br />""" % (i+1))

                out.write("""
                </div>
                <div class="codechunk">%s</div>
            </div><a href="javascript:;" onclick="togglePrev(this);">+ show +</a>""" % self._html_escape('\n'.join(s.orig_lines[context.prev_context_line:context.start_line])))
                # source info
                out.write("""
            <div>
                <div class="linenumber">""")

                for i in range(context.start_line, context.end_line):
                    out.write("""
                %d<br />""" % (i+1))

                out.write("""
                </div>
                <div class="codechunk">%s</div>
            </div>""" % self._html_escape('\n'.join(s.orig_lines[context.start_line:context.end_line])))
                # source info - next_context
                out.write("""
            <a href="javascript:;" onclick="toggleNext(this);">+ show +</a><div style="display: none">
                <div class="linenumber">""")

                for i in range(context.end_line, context.next_context_line):
                    out.write("""
                %d<br />""" % (i+1))

                out.write("""
                </div>
                <div class="codechunk">%s</div>
            </div>
        </div>""" % self._html_escape('\n'.join(s.orig_lines[context.end_line:context.next_context_line])))
            out.write("""
    </div>""")

        out.write("""
</div>
</body>
</html>""")
        out.close()

        elapsed_time = time.time() - start_time
        print('[+] \"%s\" ... %.1fs\n' % (outfile, elapsed_time))
        return exact_nmatch
