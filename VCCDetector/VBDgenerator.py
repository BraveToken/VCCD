import os
import sys
import common
import time
import hashlib

diffBinary = r"C:\Program Files\Git\usr\bin\diff.exe"


def normalize(patch):
    '''
    Normalize a patch file
    '''
    normal_lines = []
    patch = ''.join([c.group('noncomment') for c in common.c_regex.finditer(
        patch) if c.group('noncomment')])
    patch = ''.join([c.group('noncomment') for c in common.c_partial_comment_regex.finditer(
        patch) if c.group('noncomment')])
    # Remove whitespaces except newlines
    patch_lines = common.whitespaces_regex.sub("", patch).split()
    for i in range(len(patch_lines)):
        if patch_lines[i] != '':
            normal_lines.append(patch_lines[i])
    # Convert into lowercases
    return '\n'.join(normal_lines).lower()


def remove_comment(string):
    intermediate_string = ''.join([c.group('noncomment') for c in common.c_regex.finditer(
        string) if c.group('noncomment')])
    processed_string = ''.join([c.group('noncomment') for c in common.c_partial_comment_regex.finditer(
        intermediate_string) if c.group('noncomment')])
    return processed_string


def hash_list(list):
    for index, line in enumerate(list):
        if isinstance(line, str):
            line = line.encode()
            list[index] = hashlib.md5(line)
        else:
            list[index] = hash_list(list[index])
    return list


def generate_context(patch_path, old_lines):
    patchfile = open(patch_path, 'r')
    patch_lines = patchfile.readlines()
    patchfile.close()
    flag = -1
    del_nums = []
    for line in patch_lines:
        if line.startswith('--- '):
            if del_nums:
                for i in range(len(del_nums)):
                    old_lines[del_nums[i]-1] = '\n'
                del del_nums[:]
            diff_path = line.split()[1]
            if diff_path == '/dev/null':
                process_flag = False
            else:
                process_flag = True

        elif process_flag:
            if line.startswith('+++ '):
                diff_path = line.split()[1]
                if diff_path == '/dev/null':
                    process_flag = False
            elif line.startswith('@@'):
                if del_nums:
                    for i in range(len(del_nums)):
                        old_lines[del_nums[i]-1] = '\n'
                    del del_nums[:]
                flag = -int(line.split(' ')[1].split(',')[0])-1
            elif line.startswith('-'):
                flag += 1
                del_nums.append(flag)
            elif line.startswith(' '):
                flag += 1
        if del_nums:
            for i in range(len(del_nums)):
                old_lines[del_nums[i]-1] = '\n'
            del del_nums[:]
    context = normalize(''.join(old_lines)).split()
    # return hash_list(context)
    return context


def generate_V_P(patch_path):
    patch_file = open(patch_path, 'r')
    # patch_text = remove_comment(patch_file.read())
    patch_lines = patch_file.readlines()
    patch_file.close()
    # patch_lines = patch_text.splitlines(keepends=True)
    process_flag = False
    add_flag = False
    del_lines = []
    add_lines = []
    del_norm_lines = []
    add_norm_lines = []
    for line in patch_lines:
        if line.startswith('--- '):
            diff_path = line.split()[1]
            if diff_path == '/dev/null':
                process_flag = False
            else:
                process_flag = True
                hunk_cnt = -1

        elif process_flag:
            if line.startswith('+++ '):
                diff_path = line.split()[1]
                if diff_path == '/dev/null':
                    process_flag = False
            elif line.startswith('@@'):
                if add_flag:
                    add_norm_lines.append(
                        normalize(''.join(add_lines)).split())
                    del add_lines[:]
                hunk_cnt += 1
                add_flag = False
                # add_lines.append([])
            elif line.startswith('-'):
                del_lines.append(line[1:])
                # del_lines.append(md5(line[1:]))
            elif line.startswith('+'):
                add_flag = True
                # add_lines[hunk_cnt].append(line[1:])
                add_lines.append(line[1:])
                # add_lines.append(md5(line[1:]))
            elif line.startswith(' '):
                add_lines.append(line[1:])
    del_norm_lines = normalize(''.join(del_lines)).split()
    if add_flag:
        add_norm_lines.append(
            normalize(''.join(add_lines)).split())
        del add_lines[:]
    # add_norm_lines = normalize(''.join(add_lines)).split()
    # add_norm_lines = []
    # j = -1
    # for i in range(hunk_cnt+1):
    #     if add_lines[i]:
    #         add_norm_lines.append([])
    #         j += 1
    #         add_norm_lines[j] = normalize(''.join(add_lines[i])).split()
    # return hash_list(del_norm_lines), hash_list(add_norm_lines)
    return del_norm_lines, add_norm_lines
