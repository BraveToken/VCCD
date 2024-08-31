import time
import common
from metrix_generator import *
from VBDgenerator import *
from result_printer import *


def main(linebound):
    vul_dir = r'cloneFuncs\orig'
    repo = vul_dir.split('\\')[-1]
    start_time = time.time()
    if os.path.isfile(repo + '_vul.pkl'):
        VFList = common.loadList(repo + '_vul.pkl')
    else:
        # print(os.getcwd())
        VFList = list()
        start_time = time.time()
        for root, dirs, patches in os.walk(vul_dir):
            for patch in patches:
                if patch.endswith('diff'):
                    patch_path = os.path.join(root, patch)
                    # print(patch_path)
                    # old_path = '.'.join(patch_path.split('.')[0:-1])+'_OLD.c'
                    # old_path = '.'.join(patch_path.split('.')[0:-1])
                    old_path = patch_path.replace('.diff', '_OLD.c')
                    filename = old_path.split('\\')[-1].replace('_OLD.c', '.c')
                    v_func = '_'.join(filename.split('_')[3:])
                    # commit_time = int(old_path.split('\\')[-2].split('_')[-1])
                    commit_time = int(filename.split('_')[2])
                    # cve = old_path.split('\\')[-4]
                    cve = filename.split('_')[1]
                    # print(old_path)
                    try:
                        oldfile = open(old_path, 'r')
                        old_lines = oldfile.readlines()
                    except UnicodeDecodeError as err:
                        print('UnicodeDecodeError: {e}'.format(e=err))
                        print(old_path)
                        oldfile = open(old_path, 'r', encoding='windows-1252')
                        old_lines = oldfile.readlines()
                    context = generate_context(patch_path, old_lines)
                    oldfile.close()
                    # f = open('test.txt', 'w')
                    # f.writelines(context)
                    # f.close()
                    del_lines, add_lines = generate_V_P(patch_path)
                    # with open('delline.txt', 'w') as f1, open('addline.txt', 'w') as f2:
                    #     f1.writelines(del_lines)
                    #     f2.writelines(add_lines)
                    # if len(del_lines) == 0:
                    if len(context)+len(del_lines) >= linebound:
                        VFList.append(common.VFInfo(old_path, v_func, commit_time, cve, tuple(context),
                                                    tuple(del_lines), tuple(add_lines)))
        elapsed_time = time.time()-start_time
        print("[+] Generating %d Vulnerability Signatures ... %.1f" %
              (len(VFList), elapsed_time))
        # filename2 = repo + '_vul.pkl'
        # common.dumpList(VFList, filename2)

    target_dirs = [r'cloneFuncs\totalClone']
    # target_bad_dir = 'target_old\\libav'
    flag = target_dirs[0].split('\\')[0]
    if os.path.isfile(repo+'_FD_'+flag+'.pkl'):
        source_list = common.loadList(repo+'_FD_'+flag+'.pkl')
    else:
        source_list = list()
        start_time = time.time()
        for td in target_dirs:
            for root, dirs, sources in os.walk(td):
                # if root.endswith('Type-1'):
                #     continue
                for source in sources:
                    if source.endswith('.c') or source.endswith('.cpp') or source.endswith('.cxx'):
                        source_path = os.path.join(root, source)
                        filename = source_path.split('\\')[-1]
                        t_func = '_'.join(filename.split('_')[4:])
                        try:
                            # commit_time = int(source_path.split('\\')
                            #                   [-2].split('_')[-1])
                            commit_time = int(filename.split('_')[3])
                        except ValueError:
                            print(source_path)
                            raise
                        cve = filename.split('_')[0]
                        try:
                            with open(source_path, 'r') as source_file:
                                source_lines = normalize(
                                    source_file.read()).split()
                        except UnicodeDecodeError as err:
                            print(
                                'UnicodeDecodeError: {error}'.format(error=err))
                            print(source_path)
                            with open(source_path, 'r', encoding='windows-1252') as source_file:
                                source_lines = normalize(
                                    source_file.read()).split()
                        if len(source_lines) >= linebound:
                            source_list.append(common.SourceInfo(source_path,
                                                                 t_func, commit_time, cve, tuple(source_lines)))
        elapsed_time = time.time()-start_time
        print('[+] Generating %d Target Code Signatures ... %.1f' %
              (len(source_list), elapsed_time))
        # filename1 = repo+'_FD_'+flag+'.pkl'
        # common.dumpList(source_list, filename1)
    elapsed_time = time.time()-start_time
    print('[+] number of target files:', len(source_list))
    print('[+] number of vul_finger:', len(VFList))
    print('[+] time cost of first stage: %.3fs' % elapsed_time)

    with open('manual.txt', 'r') as fp:
        manual_labels = fp.readlines()
    # matched_list = match(source_list, VFList)
    # match(source_list, VFList)
    mult_match_set = mult_match(source_list, VFList, manual_labels)
    with open('VCCD_result.txt', 'w') as fp:
        for match in mult_match_set:
            fp.write(match.source_name.split('\\')
                     [-1]+' '+match.vul_list+' '+match.label+'\n')
    # # mult_match(source_list, VFList)
    # printToXlsx(matched_list)
    printToXlsx(mult_match_set)


if __name__ == '__main__':
    # linebounds = [2, 3, 4]
    # for linebound in linebounds:
    #     print('[+] linebound:', linebound)
    main(3)
