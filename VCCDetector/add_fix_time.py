import os
target_dir = 'cloneFuncs\\orig'
refer_dir = r'E:\VDBGenerator\data\vuln_patch_src_db'
default_path = os.getcwd()
for tg_file in os.listdir(target_dir):
    if tg_file.endswith('_OLD.c'):
        keyStr = '\\'.join(tg_file.split('_')[0:2])
        for root, dirs, files in os.walk(refer_dir):
            if root.endswith(keyStr):
                refer_path = root+'\\patch'
                if len(os.listdir(refer_path)) != 1:
                    print(refer_path)
                for fix_time in os.listdir(refer_path):
                    name_list = tg_file.split('_')
                    name_list.insert(3, fix_time)
                    new_name = '_'.join(name_list)
        os.chdir(target_dir)
        diff_name = tg_file.replace('_OLD.c', '.diff')
        new_diff_name = new_name.replace('_OLD.c', '.diff')
        os.rename(tg_file, new_name)
        os.rename(diff_name, new_diff_name)
    os.chdir(default_path)
