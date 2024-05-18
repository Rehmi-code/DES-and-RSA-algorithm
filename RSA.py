from random import *
import time
import decimal


def is_prime(num):
    k, p = 0, num - 1
    while (p & 1) == 0:  # 满足n - 1 = k * 2 ^ p
        p = p >> 1
        k += 1
    for j in range(6):  # 循环测试6次
        a = randint(1, num - 1)
        b = pow(a, p, num)  # a的p次方对num取余
        flag = 0
        if b == 1:
            continue  # 余数是1, 通过测试
        # 余数不是1， 进入循环
        for i in range(k):
            if (b + 1) % num == 0:
                flag = 1
                break
            else:
                b = (b * b) % num
        if flag == 1:
            continue
        else:
            return False
    return True


def generate_large_prime(size):
    """
    生成一个大素数
    :param size: 大素数的位数
    :return: num: 大素数
    """
    while True:
        num = randrange(pow(2, size - 1), pow(2, size))
        if is_prime(num):
            print("素数: ", num)
            return num


def generate_key(p, q):
    """
    产生RSA密钥
    1.选择两个大素数p和q
    2.计算n=p*q
    3.计算欧拉函数 ou_la = (p-1)*(n-1)
    4.随机选择整数e 1<e<ou_la 并且 e和ou_la互质
    5.依据等式 e * d mod(ou_la) = 1 计算数字d
    :param p: 大素数
    :param q: 大素数
    :return: RSA密钥
    """

    n = p * q
    ou_la = (p - 1) * (q - 1)
    e = 65537
    # 计算d
    d = pow(e, -1, ou_la)

    return e, n, d


def read_raw_file(file_name):
    """
    filename : 打开文件名
    return : 读取文件中字符串
    """
    try:
        fp = open(file_name, "rb")
        message = fp.read()
        fp.close()
        return str(message, 'ISO-8859-1')
    except FileNotFoundError:
        print("Open file error!")


def read_de_file(file_name):
    """
    filename : 打开文件名
    return : 读取文件中字符串
    """
    try:
        # fp = open(file_name, "r", encoding='utf-8')
        fp = open(file_name, "r", encoding='ISO-8859-1')
        raw_text = fp.read()
        fp.close()
        return raw_text
    except FileNotFoundError:
        print("Open file error!")


def write_file(text):
    """密文将写入Re.txt文件中"""
    try:
        fp = open('Re.txt', 'w', encoding='ISO-8859-1')
        fp.write(text)
        fp.close()
    except FileNotFoundError:
        print("Write file error!")


def write_de_file(message):
    """写入文件"""
    global files_name
    try:
        fp = open("D:/.Playground/cybersecurity/RSA_files/" + files_name, 'wb')
        fp.write(message)
        fp.close()
    except FileNotFoundError:
        print("Write file error!")


def str_decimal(str_message):
    """
    字符串转成十进制序列
    message ：字符串
    return ：将读入的字符串序列转化成十进制序列
    """
    bits = []
    for i in str_message:
        asc2i = bin(ord(i))[2:]  # bin将十进制数转二进制返回带有0b的'01'字符串 ord函数将字符转成对应ASCII值
        '''为了统一每一个字符的01bit串位数相同，将每一个均补齐8位'''
        # for j in range(8 - len(asc2i)):
        #     asc2i = '0' + asc2i  # 二进制
        deci_bit = str(int(asc2i, 2))  # int(,2)把2进制转10进制
        '''每个十进制不足3位补0'''
        # for k in range(3 - len(deci_bit)):
        #     deci_bit = '0' + deci_bit
        bits.append(deci_bit)
    return bits


def decimal_str(bits):  # 十进制转字符串
    """
    bits :  01比特串(长度要是3的倍数)
    returns : 对应的字符
    """
    temp = ""
    for i in range(len(bits) // 3):
        temp += chr(int(bits[i * 3:(i + 1) * 3]))  # chr将10进制转成ASCII
    return temp


def RSA_encryption(message):
    # e, n, d = generate_key(p, q)
    global e1, n1
    ciphertext = ""
    plaintext = str_decimal(message)  # 明文块
    length_n1 = len(str(n1))
    for i in plaintext:
        c = str(pow(int(i), e1, n1))  # 明文块加密过程 **是次幂运算
        for j in range(length_n1 - len(c)):  # 每块密文的位数不会超过n1的位数
            c = '0' + c
        ciphertext += c

    write_file(ciphertext)
    return ciphertext


def RSA_decryption(de_file):
    global n1, d1
    print("n:", n1)
    print("d:", d1)
    cipher = []
    plaintext = ""
    message = read_de_file(de_file)
    length_n1 = len(str(n1))
    length_message = len(message)
    for i in range(0, length_message, length_n1):
        mes_block = ""
        for j in range(length_n1):
            mes_block += message[i + j]
        cipher.append(mes_block)
    length_ciper = len(cipher)
    for i in range(length_ciper):
        m = str(pow(decimal.Decimal(cipher[i]), d1, n1))  # 恢复明文过程
        if len(m) < 3:
            for j in range(3 - len(m)):
                m = '0' + m  # 不足3位补0
        plaintext += m

    plaintext = decimal_str(plaintext)
    return plaintext


def start():
    global e1, n1, d1
    global files_name
    print("Encrypt press 0   Decrypt press 1   Exit press 2:", end='')
    t = input()
    if t == '0':
        print("输入要加密的文件: ", end='')
        files_name = input()
        p_in = generate_large_prime(45)  # 35万亿到70万亿
        q_in = generate_large_prime(45)
        file_content = read_raw_file(files_name)
        e1, n1, d1 = generate_key(p_in, q_in)
        tic = time.perf_counter()
        cipher_text = RSA_encryption(str(file_content))
        write_file(cipher_text)
        toc = time.perf_counter()
        print(f"加密完成, 用时{toc - tic:0.4f}秒")
    elif t == '1':
        print("输入要解密的文件: ", end='')
        filename_c = input()
        tic = time.perf_counter()
        plain_text = RSA_decryption(filename_c)
        toc = time.perf_counter()
        write_de_file(plain_text.encode('ISO-8859-1'))
        print(f"解密完成, 用时{toc - tic:0.4f}秒")
    elif t == '2':
        print("EXIT!")
        return True
    else:
        print("Input error!")


if __name__ == "__main__":
    e1, n1, d1 = 0, 0, 0
    files_name = ""
    while True:
        if start():
            break
