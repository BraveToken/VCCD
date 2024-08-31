import os
from collections import defaultdict

vuln_dir = r'E:\cloneFuncs\vuln'
repo_cve_dict = defaultdict(set)
for vuln in os.listdir(vuln_dir):
    repo = vuln.split('_')[0]
    cve = vuln.split('_')[1]
    repo_cve_dict[repo].add(cve)
for repo in repo_cve_dict:
    print(repo, len(repo_cve_dict[repo]))
