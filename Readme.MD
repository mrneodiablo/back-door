#                  Backup Door

Các thư mục sẽ là các loại back door mình viết bằng pythong, sẽ update nhiều tính năng cho back door trong thời gian tới. Hiện tại chỉ hổ trợ shell đơn giản


## icmp_reverse_shell

```
Sử dụng icmp để send payload nên khó bị phát hiện bới firewall.
```

Client gởi gói ICMP ECHO REQUEST  tới server, server send command bằng gói replay


## TCP_NETCAT

```
Sử dụng python socket native để viết, client và attacker, server là victim,
gởi raw data qua tcp socket để control
```

## UDP_NETCAT

```
Sử dụng gói UDP thay vì gói TCP dể bị phát hiên
```