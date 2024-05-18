from DES_BOX import *
import time


def read_raw_file(filename):
    """
    filename : 打开文件名
    return : 读取文件中字符串
    """
    try:
        fp = open(filename, "rb")
        message = fp.read()
        fp.close()
        return str(message, 'ISO-8859-1')
    except FileNotFoundError:
        print("Open file error!")


def read_de_file(filename):
    """
    filename : 打开文件名
    return : 读取文件中字符串
    """
    try:
        fp = open(filename, "r", encoding='ISO-8859-1')
        # fp = open(filename, "rb")
        message = fp.read()
        fp.close()
        return message
    except FileNotFoundError:
        print("Open file error!")


def write_file(message):
    """密文将写入De.txt文件中"""
    try:
        # fp = open('De.txt', 'w', encoding='utf-8')
        fp = open('De.txt', 'w', encoding='ISO-8859-1')
        fp.write(message)
        fp.close()
    except FileNotFoundError:
        print("Write file error!")


def write_de_file(message):
    """写入文件"""
    global file_name
    try:
        fp = open("D:/.Playground/cybersecurity/DES_files/" + file_name, 'wb')
        fp.write(message)
        fp.close()
    except FileNotFoundError:
        print("Write file error!")


def str_bit(message):
    """
    message ：字符串
    return ：将读入的字符串序列转化成01比特流序列
    """
    bits = ""
    for i in message:
        asc2i = bin(ord(i))[2:]  # bin将十进制数转二进制返回带有0b的'01'字符串 ord函数将字符转成对应ASCII值
        '''为了统一每一个字符的01bit串位数相同，将每一个均补齐8位'''
        for j in range(8 - len(asc2i)):
            asc2i = '0' + asc2i
        bits += asc2i
    return bits


def process_key(key):  # 生成64位密钥
    """
    key : 输入的密钥字符串
    return : 64bit 01序列密钥(采用偶校验的方法)
    """
    key_bits = ""
    for i in key:
        count = 0
        asc2i = bin(ord(i))[2:]
        '''将每一个ascii均补齐7位,第8位作为奇偶效验位'''
        for j in asc2i:
            count += int(j)
        for j in range(7 - len(asc2i)):  # 补齐7位
            asc2i = '0' + asc2i
        # 第8位校验位
        if count % 2 == 0:
            asc2i += '0'
        else:
            asc2i += '1'

        # for j in range(7 - len(asc2i)):
        #     asc2i = '0' + asc2i
        key_bits += asc2i
    if len(key_bits) > 64:
        return key_bits[0:64]
    else:
        for i in range(64 - len(key_bits)):
            key_bits += '0'
        return key_bits


def divide(bits, bit):  # 将数据按照bit参数进行分组 明文分组长度64位
    """
    bits : 将01bit按bit一组进行分组
    return : 按bit位分组后得到的列表
    """
    m = len(bits) // bit  # 分成m组
    N = ["" for _ in range(m)]
    for i in range(m):
        N[i] = bits[i * bit:(i + 1) * bit]

    if len(bits) % bit != 0:
        N.append(bits[m * bit:])
        for i in range(bit - len(N[m])):
            N[m] += '0'  # 不足bit位补0
    return N  # N列表里是分好组的数据 每组64位


def IP_change(bits):  # 初始置换IP
    """
    bits:一组64位的01比特字符串
    return：初始置换IP后64bit01序列
    """
    ip_str = ""
    for i in IP:
        ip_str = ip_str + bits[i - 1]
    return ip_str


def PC_1_change(key):  # 交换选择1 用于生成16个48位的子密钥
    """
    key:64bit有效密钥01bit字符串
    return:密钥置换PC-1后56bit01字符串
    """
    pc_1 = ""
    for i in PC_1:
        pc_1 = pc_1 + key[i - 1]
    return pc_1


def key_leftshift(key_str, num):  # 循环左移 num表示左移位数  用于生成16个48位的子密钥
    """
    key_str : 置换PC-1后的28bit01字符串
    return : 28bit01字符串左移num位后的结果
    """
    left = key_str[num:28]
    left += key_str[0:num]
    return left


def PC_2_change(key):  # 交换选择2 从56位输入选48位输出 用于生成16个48位的子密钥
    """
    key : 56bit移位后密钥01bit字符串
    return : 密钥置换PC-2后48bit序列字符串
    """
    pc_2 = ""
    for i in PC_2:
        pc_2 = pc_2 + key[i - 1]
    return pc_2


def generate_key(key):  # 生成16个子密钥，返回列表
    """
    key : 64bit01密钥序列
    return : 16轮的16个48bit01密钥列表按1-16顺序
    """
    key_list = ["" for _ in range(16)]
    key = PC_1_change(key)  # 置换PC_1
    key_left = key[0:28]  # 左28位
    key_right = key[28:]  # 右28位
    for i in range(len(SHIFT)):  # SHIFT表示循环左移位数
        key_left = key_leftshift(key_left, SHIFT[i])
        key_right = key_leftshift(key_right, SHIFT[i])
        key_i = PC_2_change(key_left + key_right)  # 置换PC_2
        key_list[i] = key_i
    return key_list


def E_change(bits):  # 选择拓展  输入的32位变成48位
    """
    bits : 32bit01序列字符串
    return : 扩展置换E后的48bit01字符串
    """
    e = ""
    for i in E:
        e = e + bits[i - 1]
    return e


def xor(bits, ki):  # 异或
    """
    bits : 48bit01字符串 / 32bit01 F加密函数输出
    ki : 48bit01密钥序列 / 32bit01 Li
    return ：bits与ki异或运算得到的48bit01 / 32bit01
    """
    bits_xor = ""
    for i in range(len(bits)):
        if bits[i] == ki[i]:
            bits_xor += '0'
        else:
            bits_xor += '1'
    return bits_xor


def s(bits, i):  # 用于选择压缩运算 i表示使用第几个S盒
    """
    bits : 6 bit01字符串
    i : 使用第i个s盒
    return : 4 bit01字符串
    """
    row = int(bits[0] + bits[5], 2)  # 得到第几行
    col = int(bits[1:5], 2)  # 得到第几列
    num = bin(S[i - 1][row * 16 + col])[2:]  # 根据行和列得到数据
    for i in range(4 - len(num)):  # 补齐4位
        num = '0' + num
    return num


def S_change(bits):  # 选择压缩运算  48位分成8组，每组6位，8个S盒的输出连在一起是32位
    """
    bits : 异或后的48bit01字符串
    return : 经过S盒之后32bit01字符串
    """
    s_change = ""
    for i in range(8):
        temp = bits[i * 6:(i + 1) * 6]
        temp = s(temp, i + 1)
        s_change += temp
    return s_change


def P_change(bits):  # 置换运算
    """
    bits : 经过S盒后32bit01字符串
    returns : 置换P后32bit01输出序列
    """
    p = ""
    for i in P:
        p = p + bits[i - 1]
    return p


def F(bits, ki):  # 加密函数
    """
    bits : 32bit 01 Ri输入
    ki : 48bit 第i轮密钥
    return : F函数输出32bit 01序列串
    """
    bits = xor(E_change(bits), ki)
    bits = P_change(S_change(bits))
    return bits


def IP_RE_change(bits):  # 逆初始置换
    """
    bits : 经过16轮迭代的64bit01字符串
    returns : 逆初始置换得到64bit密文01字符串
    """
    ip_re = ""
    for i in IP_RE:
        ip_re += bits[i - 1]
    return ip_re


def des_encrypt(bits, key):  # 加密流程
    """
    bits : 分组64bit 01明文字符串
    key : 64bit01密钥
    return : 加密得到64bit 01密文序列
    """
    bits = IP_change(bits)
    # 切片分成两个32bit
    L = bits[0:32]
    R = bits[32:]
    key_list = generate_key(key)  # 16个密钥
    # 乘积变换 16轮迭代
    for i in range(16):
        L_next = R
        R = xor(L, F(R, key_list[i]))
        L = L_next
    result = IP_RE_change(R + L)
    return result


def des_decrypt(bits, key):
    """
    bits : 分组64bit 01加密字符串
    key : 64bit01密钥
    return : 解密得到64bit 01密文序列
    """
    bits = IP_change(bits)
    # 切片分成两个32bit
    L = bits[0:32]
    R = bits[32:]
    key_list = generate_key(key)  # 16个密钥
    for i in range(16):
        L_next = R
        R = xor(L, F(R, key_list[15 - i]))
        L = L_next
    result = IP_RE_change(R + L)
    return result


def bit_str(bits):  # 二进制转字符串
    """
    bits :  01比特串(长度要是8的倍数)
    returns : 对应的字符
    """
    temp = ""
    for i in range(len(bits) // 8):
        temp += chr(int(bits[i * 8:(i + 1) * 8], 2))
    return temp


def all_des_encrypt(message, key):
    """
    message : 读入明文字符串
    key : 读入密钥串
    returns : 密文01序列
    """
    message = str_bit(message)
    key = process_key(key)
    mess_div = divide(message, 64)
    result = ""
    for i in mess_div:
        result += des_encrypt(i, key)
    return result


def all_des_decrypt(message, key):
    """
    message : 读入密文字符串
    key : 读入密钥串
    returns : 明文01序列串
    """
    # message = str_bit(message)
    key = process_key(key)
    mess_div = divide(message, 64)
    result = ""
    for i in mess_div:
        result += des_decrypt(i, key)
    return result


def start():
    print("Encrypt press 0   Decrypt press 1   Exit press 2:", end='')
    global file_name
    t = input()
    if t == '0':
        print("输入要加密的文件: ", end='')
        message = input()
        file_name = message
        message = read_raw_file(message)
        print("输入你设置的密码:", end='')
        key = input()
        tic = time.perf_counter()
        result = all_des_encrypt(message, key)
        write_file(result)
        toc = time.perf_counter()
        print(f"加密完成, 用时{toc - tic:0.4f}秒")

    elif t == '1':
        print("输入要解密的文件: ", end='')
        message = input()
        message = read_de_file(message)
        print("输入你设置的密码:", end='')
        key = input()
        tic = time.perf_counter()
        result = all_des_decrypt(message, key)
        result_str = bit_str(result)
        toc = time.perf_counter()
        write_de_file(result_str.encode('ISO-8859-1'))

        print(f"解密完成, 用时{toc - tic:0.4f}秒")
    elif t == '2':
        print("EXIT!")
        return True
    else:
        print("Input error!")


if __name__ == '__main__':
    file_name = ""
    while True:
        if start():
            break
