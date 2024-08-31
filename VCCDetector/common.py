from collections import namedtuple
import re
import pickle
# try:
#     # import pandas as pickle
#     import _pickle as pickle
# except:
#     import cPickle as pickle
VFInfo = namedtuple(
    'VFInfo', ['path', 'filename', 'time', 'cve', 'context', 'del_lines', 'add_lines'])
SourceInfo = namedtuple(
    'SourceInfo', ['path', 'filename', 'time', 'cve', 'source_lines'])
MatchInfo = namedtuple('MatchInfo', ['source_name', 'vul_list', 'label'])
MissInfo = namedtuple('MissInfo', ['missed_name'])

# regex for comments
c_regex = re.compile(
    r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"{}]*)',
    re.DOTALL | re.MULTILINE)
c_partial_comment_regex = re.compile(
    r'(?P<comment>/\*.*?$|^.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"{}]*)', re.DOTALL)
# regex for whitespaces except newlines
whitespaces_regex = re.compile(r'[\t\x0b\x0c\r ]+')


def dumpList(tupList, filename):
    # f = open(filename, 'a+')
    f = open(filename, 'ab+')
    pickle.dump(tupList, f)
    f.close()


def loadList(filename):
    f = open(filename, 'rb')
    tupList = pickle.load(f)
    f.close()
    return tupList
