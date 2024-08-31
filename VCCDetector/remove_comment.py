import common


def remove_comment(string):
    intermediate_string = ''.join([c.group('noncomment') for c in common.c_regex.finditer(
        string) if c.group('noncomment')])
    processed_string = ''.join([c.group('noncomment') for c in common.c_partial_comment_regex.finditer(
        intermediate_string) if c.group('noncomment')])
    return processed_string


file = r'cloneFuncs\orig\linux_CVE-2019-15031_1567572928_check_if_tm_restore_required.diff'
with open(file, 'r') as fp:
    text = remove_comment(fp.read())
lines = text.splitlines(keepends=True)
print(''.join(lines))
