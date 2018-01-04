import sys
import socket
import getopt
import threading
import subprocess

# defind global variable
listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0


def usage():
    data = """
    DONGVT Net Tool

    -------------------------------------------------------------
    Usage: DVTnet.py -t target_host -p port

    -l  --listen                    - listen on [host]:[port] cho ket noi toi
    -e --execute=file_to_run        - execute file duoc nhan tu connection
    -c --command                    - chay command shell 
    -u --upload=destination         - upload file [destination]

    --------------------------------------------------------------
    Examples: 

    DVTnet.py -t 192.168.0.1 -p 5555 -l -c
    DVTnet.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe
    DVTnet.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\"
    echo 'ABCDEFGHI' | ./DVTnet.py -t 192.168.11.12 -p 135

    """

    print data
    sys.exit(0)



# tao client send data
def client_sender(buffer):

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect((target, port))

        if len(buffer):
            client.send(buffer)
        else:
            # cho cho data back
            while True:
                recv_len = 1
                respone = ""

                while recv_len:
                    data = client.recv(4096)
                    recv_len = len(data)
                    respone += data
                    if recv_len < 4096:
                        break

                print respone,

                buffer = raw_input("")
                buffer += "\n"


                # sent it to off
                client.send(buffer)

    except:
        print "[*] Exception! Exiting."
        client.close()
        sys.exit(0)

def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target

    port = 2222
    target = "localhost"

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu:", ["help","listen","execute","target","port","command","upload"])
    except getopt.GetoptError as e:
        print e
        usage()

    for o,a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            listen = True
        elif o in ("-e", "--execute"):
            execute = a
        elif o in ("-c", "--commandshell"):
            command = True
        elif o in ("-u", "--upload"):
            upload_destination = a
        elif o in ("-t", "--target"):
            target = a
        elif o in o in ("-p", "--port"):
            port = int(a)
        else:
            assert False, "Unhandled Option"


    if not listen and len(target) and port > 0:

        # doc trong buffer tu commandline
        buffer = sys.stdin.read()
        client_sender(buffer)


if __name__ == '__main__':
    main()
