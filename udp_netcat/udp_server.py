import  socket
import threading

global IP
global PORT

IP = "0.0.0.0"
PORT  = 12345

def udp_server(server):
    while True:
        data, addr = server.recvfrom(4096)
        print "%s: %d --> %s" % (addr[0], addr[1], data)
        server.sendto("ACK!" + data, (addr[0], addr[1]))


if __name__ == '__main__':

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((IP, PORT))
    print "[*] Server UDP listen %s: %d" % (IP, PORT)

    while True:
        sv = threading.Thread(target=udp_server, args=(server,))
        sv.run()




