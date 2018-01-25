Trong phần này mình sẽ build ICMP để controll host reverse

====IP HEADER

=========================================================
| version | header length | service type | total length |
|-------------------------------------------------------|
|     Identification    | flag |     Fragment Offset    |
|-------------------------------------------------------|
|  TTL    | protocol | header checksum                  |
|-------------------------------------------------------|
|              Source IP Address                        |
|-------------------------------------------------------|
|              Destination IP Address                   |
|-------------------------------------------------------|
|      Option               | Padding                   |
|=======================================================|

[version] 4 bit: thông tin version v4/v6
[header lenth] 4 bit: độ dài header
[type of service] 8 bit: để ưu tiên gói
[total lenth] 16 bit: tổng độ dài
[Identification] 16 bit: chỉ số của 1 gói patcket (ví dụ khi data chia thành nhiều packet thì mỗi packet có 1 identifi khác nhau)
[Flag] 3 bit: báo gói tim có phân mảnh hay không, hay nói cách khác là có phải là gói tin cuối của hay không
[Fragment Offset] 13 bit: báo vị trí offset của các mảnh so với gới IP datagram gốc ví dụ gói 1 offset = 0, gói 1 total len là 1500 thì gói 2 offset sẽ là 1501
[time to live] 8 bit: chỉ số hop mà gói tin có thể đi qua, khi qua 1 router thì nó sẽ -1, nếu sau khi -1 = 0 thì nó sẽ echo replay
[Protocol] 8 bit: chỉ ra giao thức tần trên là gì
[header check sum] 16 bit: giúp router check sum lỗi bit trong ip header, giúp đảm bảo tính toàn vẹn header
[Source IP Address] 32 bit
[Destination IP Address] 32 bit
[IP option]

== ICMP HEADER

--------------------------ICMP-------------------------------------------------|
[type of message]  8 bit                                                       |
[code]             8 bit                                                       |
[check sum]        16 bit                                                      |
[indentifier BE LE]    2 byte                                                  |
[Sequence number BE LE]2 byte                                                  |
[payload data] optional 32 byte <maximun là 578 byte>                          |
-------------------------------------------------------------------------------|
0 : echo replay
3: destination unreachable
4: source quench
5: redirect
6: alternate host adress
8: echo request
9: router advertisement
10 router selection
11: time exceeded
12: Parameter problem
13: timestamp
14: timestamp replay
15: info request
16: info replay
17: adress mask request
18: adress mask replay


|---------------|                                 |-------------|
|    server     |                                 |             |
|               |           <------------------   |    client   |
|---------------|                                 |-------------|


Quy định protocol ICMP để control shell


1 // CLIENT  --> echo request  -->  [SERVER]

    byte thứ 28 quy định là gói tin loại gì

(client)     0   :  là gói thông tin của victim (gói đầu tiền khi start client sẽ lập trức gởi gói này cho server)
(server)     1   :  là gói bỏ qua không có command
(server)     2   :  là gói gởi lệnh thực hiện
(client)     3   :  là gói respone data
(client)     4   :  la goi respone None


