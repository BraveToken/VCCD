import difflib


def LCS(str1, str2):
    c = [[0 for i in range(len(str2)+1)] for j in range(len(str1)+1)]
    for i in range(1, len(str1)+1):
        for j in range(1, len(str2)+1):
            if str1[i-1] == str2[j-1]:
                c[i][j] = c[i-1][j-1] + 1
            else:
                c[i][j] = max(c[i][j-1], c[i-1][j])
    # print(c)
    return c[-1][-1]


def calComLen(list1, list2):
    # with open('text1.txt', 'w') as f1, open('text2.txt', 'w') as f2:
    #     f1.write('\n'.join(list1))
    #     f2.write('\n'.join(list2))
    # diffCmd = "\"{0}\" -u {1} {2} > {3}".format(
    #     diffBinary, 'text1.c', 'text2.c', 'text3.txt')
    # diffCmd = [diffBinary, '-u', 'text1.txt', 'text2.txt', '>', 'text3.txt']
    # subprocess.Popen(diffCmd)
    # os.system(diffCmd)
    # with open('text3.txt') as f3:
    #     diff_lines = f3.readlines()
    diff_lines = difflib.unified_diff(list1, list2)
    del_num = 0
    for line in diff_lines:
        if line.startswith('--- '):
            continue
        elif line.startswith('-'):
            del_num += 1
    return len(list1)-del_num


def iscontain(C, F):
    len_C = len(C)
    len_F = len(F)
    if len_F == 0:
        return True
    result = False
    if len_C < len_F:
        result = False
    else:
        m = 0
        for n in range(len_C):
            if C[n] == F[m]:
                m += 1
                if m == len_F:
                    result = True
                    break
    # result = m
    return result


def KMP_algorithm(string, substring):
    '''
    KMP字符串匹配的主函数
    若存在字串返回字串在字符串中开始的位置下标，或者返回-1
    '''
    pnext = gen_pnext(substring)
    n = len(string)
    m = len(substring)
    i, j = 0, 0
    while (i < n) and (j < m):
        if (string[i] == substring[j]):
            i += 1
            j += 1
        elif (j != 0):
            j = pnext[j-1]
        else:
            i += 1
    if (j == m):
        return True
    else:
        return False


def gen_pnext(substring):
    """
    构造临时数组pnext
    """
    index, m = 0, len(substring)
    pnext = [0]*m
    i = 1
    while i < m:
        if (substring[i] == substring[index]):
            pnext[i] = index + 1
            index += 1
            i += 1
        elif (index != 0):
            index = pnext[index-1]
        else:
            pnext[i] = 0
            i += 1
    return pnext
