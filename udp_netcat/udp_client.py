import  socket

if __name__ == '__main__':

    target_host = "0.0.0.0"
    target_port = 12346

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


    while True:
        print "<DONG:#> "
        data = raw_input("")
        client.sendto(data,(target_host, target_port))
        data , addr = client.recvfrom(4096)
        print data

