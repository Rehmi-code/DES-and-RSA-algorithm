def tobinary(a):  # 转化为二进制
    d = []
    c = a
    while (c != 0):
        b = c % 2
        c = int(c / 2)
        d.append(b)
    return d


def quickmi(m, e, n):  # 快速幂算法
    f = tobinary(e)
    c = 0
    d = 1
    while (c != e):
        c = 2 * c
        d = (d * d) % n
        g = f.pop()
        if (g == 1):
            c = c + 1
            d = (d * m) % n
    return d


if __name__ == '__main__':
    m = 2354444444444
    e = 22033964424223543455555555555
    n = 4144181163644921454
    print(quickmi(m, e, n))
