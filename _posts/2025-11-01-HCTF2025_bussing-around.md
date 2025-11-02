---
title: "Day 18: Bussing Around"
categories:
- Huntress CTF 2025 Writeups
- writeups
tags:
  - writeup
  - forensics
  - network forensics
  - Huntress CTF 2025
date: 2025-11-01
description: "One of the engineers noticed that an HMI way going haywire ... Can you help us figure out what's going on?"
author: hex4a
image:
  path: assets/img/huntress2025/bussing_around/wiresharklogo.png
  alt:
  post: false
---
## Challenge Info

- **Name**: Bussing Around
- **Category**: Forensics
- **Points**: 10
- **Author**: @Soups71

## Challenge Description
```
One of the engineers noticed that an HMI was going haywire.

He took a packet capture of some of the traffic but he can't make any sense of it... it just looks like gibberish!

For some reason, some of the traffic seems to be coming from someone's computer. Can you help us figure out what's going on?
```
**Challenge File:** [`bussing_around.pcapng`](/assets/challenge_files/huntress2025/bussing_around/bussing_around.pcapng)
## Solution

Knowing that this packet capture relates to an HMI, which is an ICS system - Interesting! After opening the `.pcapng` in Wireshark, we're greeted with a bunch of [Modbus](https://en.wikipedia.org/wiki/Modbus) traffic (specifically MODBUS/TCP) 

![](/assets/img/huntress2025/bussing_around/wireshark_cap_1.png)

Coming into this challenge, I was unfamiliar with the Modbus protocol. Reading into the data structure and various implementations, we can see that this implementation is `Modbus/TCP` (or `Modbus TCP/IP`). 

Getting into  `Modbus/TCP` specifications, I'm going to lead with some basics:
- Modbus protocols are often used to communicate with RTUs (Remote Terminal Units)
- Any device that sends out a Modbus command is the **client**, and the responding device is the **server**.
- For this challenge, it's important not to overthink the process as you look through this packet capture.

Reading more into the protocol, we can see that the Modbus TCP/IP ADU is specified specified as `MBAP Header + Function code + Data`, with the MBAP (MODBUS Application Protocol) Header structure as follows:

| Name           | Len (Bytes) | Function                                                                              |
| -------------- | ----------- | ------------------------------------------------------------------------------------- |
| Transaction ID | 2           | Message synchronization between server and client                                     |
| Protocol ID    | 2           | 0 for Modbus/TCP                                                                      |
| Length         | 2           | Number of remaining bytes in the frame                                                |
| Unit           | 1           | Server address (255 if unused), treated like slave address in Modbus over Serial line |

The frame structure would then be:

| Transaction ID | Protocol ID | Length  | Unit ID | Function code | Data      |
| -------------- | ----------- | ------- | ------- | ------------- | --------- |
| 2 bytes        | 2 bytes     | 2 bytes | 1 bytes | 1 bytes       | *n* bytes |
Looking at a Modbus packet in Wireshark:

![](/assets/img/huntress2025/bussing_around/wireshark_modbus_packet.png)

Following the TCP stream, we can see that command queries are being echoed by the server, so we know to filter for only queries or responses.

![](/assets/img/huntress2025/bussing_around/wireshark_tcp_stream.png)

With our knowledge of the MBAP, we can filter our modbus traffic and learn which function codes are being used here:
```zsh
➜ tshark -r bussing_around.pcapng -Y "ip.src==172.20.10.2 && mbtcp.prot_id==0" \
-T fields -e modbus.func_code | sort -u
5
6
```
Great! We can see that the functions used here are 5 (Write single coil) and 6 (Write Single Holding Register). We're going to check the Modbus data for each of these to see where data might be hiding.
Starting with function 5 (Write Single Coil), we can see the values `ff00` ("on" / binary 1) and `0000` ("off" / binary 0).
```zsh
➜ tshark -r bussing_around.pcapng -Y "ip.src==172.20.10.2 && modbus.func_code==5" \
-T fields -e modbus.data | sort -u
0000
ff00
```
Checking to see if we can construct the flag from a base-2/binary data stream:
```zsh
➜ tshark -r bussing_around.pcapng -Y "ip.src==172.20.10.2 && modbus.func_code==5" \
-T fields -e modbus.data | resplit [| repl '0000' 0 | repl 'ff00' 1 ] | base 2
��fPa����m����Z7����n���675��w�����H���b���Vs�AJ֊���.q�
                                                       i�ة������4ˊ|��ݢP1�E���Ѡ�jz�%Ũ�n���L��clo�NW7�9Xt����}�{
```
I can assure you much time was spent checking if this was some compressed or encrypted data, but this unfortunately was a dead end.

Next, I looked at the function 6 data

![](/assets/img/huntress2025/bussing_around/function_6_data.png)

This data looked like it could've been many things - especially when splitting up by register, I thought there may be some interesting encoding at play with the dumped register 4 data:

![](/assets/img/huntress2025/bussing_around/interesting_register_data.png)

However, after almost four (4) days of overthinking, we put our heads together to attempt to _underthink_, and thought about checking for binary numbers without separating the registers:

![](/assets/img/huntress2025/bussing_around/binary_data_from_registers.png)

Well look at that! Decoding the binary number data:
```zsh
➜ tshark -r bussing_around.pcapng -Y "ip.src==172.20.10.2 && modbus.func_code==6" \
-T fields -e modbus.data | resplit [| rex '000[01]' | snip 3: ] | base 2
PK
        �V:[�Th�3flag.txtUT     ���h��hux
                                         ���}��␦8*à�A8�v��U����H%��␦�Q�&�QN��8h��1��+��P�Th�3'PK
        �V:[�Th�3��flag.txtUT���hux
                                   ��PKN�2The password is 5939f3ec9d820f23df20948af09a5682 .
```
After days of overthinking, I'm greeted with an encrypted zip file! And it even kindly tells us the password!
```zsh
➜ tshark -r bussing_around.pcapng -Y "ip.src==172.20.10.2 && modbus.func_code==6" \
-T fields -e modbus.data | resplit [| rex '000[01]' | snip 3: ] | base 2 \
| dump the_flag.zip; unzip -P 5939f3ec9d820f23df20948af09a5682 the_flag.zip; cat flag.txt
Archive:  the_flag.zip
The password is 5939f3ec9d820f23df20948af09a5682 .
 extracting: flag.txt
flag{4d2a66c5ed8bb8cd4e4e1ab32c71f7a3}
```
Bingo!
## Flag

```
flag{4d2a66c5ed8bb8cd4e4e1ab32c71f7a3}
```

## Notes

It's extremely important to get some fresh air and new perspectives during long CTF events like this - as challenges get harder, you might start to expect more complicated techniques, but don't let that cloud your decision-making processes! 
