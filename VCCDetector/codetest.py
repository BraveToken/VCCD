def get_pnext(S):
    pre, i = 0, 1
    pnext = [0] * len(S)
    while i < len(S) - 1:
        if S[pre] == S[i]:
            i += 1
            pre += 1
            pnext[i] = pre
        elif pre != 0:
            pre = pnext[pre]
        else:
            i += 1
            pnext[i] = 0
    return pnext


S = "ababab"
pnext = get_pnext(S)
print(pnext)
