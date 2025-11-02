---
title: "Day 26: Puzzle Pieces Redux"
categories:
  - Huntress CTF 2025 Writeups
  - writeups
tags:
  - writeup
  - forensics
  - static analysis
  - Huntress CTF 2025
date: 2025-11-01
description: Well, I accidentally put my important data into a bunch of executables ... It was fine... until my cat Sasha stepped on my keyboard and messed everything up! 
author: hex4a
image:
  path: /assets/img/huntress2025/puzzle_pieces_redux/bingus_forensics_puzzle.png
  alt:
  post: false
---
## Challenge Info
- **Name**: Puzzle Pieces Redux
- **Category**: Forensics
- **Points**: 10
- **Author**: @Nordgaren

## Challenge Description
```
Well, I accidentally put my important data into a bunch of executables... just don't ask, okay?

It was fine... until my cat Sasha stepped on my keyboard and messed everything up! OH NOoOoO00!!!!!111

Can you help me recover my important data?
```
**Challenge File:** [`puzzle-pieces-redux.7z`](/assets/challenge_files/huntress2025/puzzle_pieces_redux/puzzle-pieces-redux.7z)
## Solution

Upon unzipping the challenge file archive, we're greeted with a handful of .bin files - let's identify their filetypes to put this puzzle together! 
[](/assets/img/huntress2025/puzzle_pieces_redux/binfiles.png)

```zsh
➜ ef ** [| run "file {path}" ]]
07c8b8cb6a9.bin: PE32+ executable (console) x86-64, for MS Windows
1a1962fc.bin: PE32+ executable (console) x86-64, for MS Windows
20a.bin: PE32+ executable (console) x86-64, for MS Windows
3511c0a625.bin: PE32+ executable (console) x86-64, for MS Windows
5eb6e6c8.bin: PE32+ executable (console) x86-64, for MS Windows
64b.bin: PE32+ executable (console) x86-64, for MS Windows
6676585.bin: PE32+ executable (console) x86-64, for MS Windows
7c8394d4b6b0.bin: PE32+ executable (console) x86-64, for MS Windows
99fa27fd897.bin: PE32+ executable (console) x86-64, for MS Windows
a6ffddda.bin: PE32+ executable (console) x86-64, for MS Windows
a891a220.bin: PE32+ executable (console) x86-64, for MS Windows
abc9.bin: PE32+ executable (console) x86-64, for MS Windows
c931.bin: PE32+ executable (console) x86-64, for MS Windows
d2def806d493f.bin: PE32+ executable (console) x86-64, for MS Windows
db887b5440.bin: PE32+ executable (console) x86-64, for MS Windows
e75147c1b1b9406.bin: PE32+ executable (console) x86-64, for MS Windows
```

Nice, they're all **PE32** binaries! I like to work in WSL2, so that I have the ability to run both Unix- and Windows-specific tools. With WSL, I can use refinery to run each file and print the path and output right from zsh!  

```zsh
➜ ef ** [| push [| run ./{path} | pop output | pf {path} {output} ]]
07c8b8cb6a9.bin 5abfa
1a1962fc.bin f9f73
20a.bin d85d5
3511c0a625.bin 16f73
5eb6e6c8.bin 49f8b
64b.bin e6817
6676585.bin 02}
7c8394d4b6b0.bin d9c1a
99fa27fd897.bin 23c
a6ffddda.bin 88a2d
a891a220.bin flag{
abc9.bin 48979
c931.bin 5f93f
d2def806d493f.bin 9bfc2
db887b5440.bin be7a1
e75147c1b1b9406.bin f18ba
```

Now that we know what files they are, and that these binaries are seemingly printing flag parts, we have to find out which of them produce a *correct* flag part, and how they're ordered. 
The gimmick here is actually quite simple, and the challenge description gives a great hint - let's grab the "Sasha" (Sha-256) hashes of each of these binaries within this refinery pipeline.

```zsh
➜ ef ** [| push [| sha256 -t | pop checksum | push [| run ./{path} | pop output \
| pf {path} {checksum} {output} ]]]]
07c8b8cb6a9.bin 45951368223b60ee10f964785f96251fbfd2988af1c7cbb66bd27570ed000000 5abfa
1a1962fc.bin 3a389838f872c04ee98b56b47b026c56e9e1bf9a791d33f07991d72c8eb20083 f9f73
20a.bin 7f0c897e241ac92d0c4c9ecf680cf8c570c72cc2a1a99ab50ce218c518fd0000 d85d5
3511c0a625.bin 79ec81fe08fded6518d296f50e9d9ef1524ea0c95d88b94b376834351ee53485 16f73
5eb6e6c8.bin dec0721f3014e22cb1b121f065adaa6debf070c4dc86d4446cb3d6cb87300000 49f8b
64b.bin 3bd187f44e284ff90986ed67104a53cff73fed14a55902a343a86a2108e7f000 e6817
6676585.bin aecc3b8b3b871ac034c60ddb7c0698105bcf4c768603a0b4f64e3a1100000000 02}
7c8394d4b6b0.bin b8f23f0b8cb91161a8a757dc74d7f89d634f2bb50455233425105e44511150a5 d9c1a
99fa27fd897.bin 598ef46397a9dbf5fe468543022f72a8014f7d0b9448058955f896914fa53f57 23c
a6ffddda.bin 27f1c4dad4c5e5bc3369adde78dc739121acd64a9549587f9f82a83b520f8704 88a2d
a891a220.bin ee1520fbe2b1dc1bb85321ddc602aa043f7728440e48524fb1b67e1b272822e0 flag{
abc9.bin 0fd014cc10ca48f4c65e9be49914aa0c7e24a19c561801541185473e8a08f9a4 48979
c931.bin d81c9372e8fe20e0917bfee218a8e9c78bdb4a41ad2f234b1d28865aa1eb7669 5f93f
d2def806d493f.bin 0b8b764a058b59bcb7868e3c402119b50ca02e6fb6eb98deec4821efcd82c29b 9bfc2
db887b5440.bin 016f23e8ac531cec3da547a0e0bc732b4ce96d26306c83b38ec14f7bd2a9e700 be7a1
e75147c1b1b9406.bin 3a9d1b97597e38008e13e2ba64667667bb1a6cdc43b905a826d91496b0000000 f18ba
```

We can see some of these binaries have trailing zeroes! The binary that outputs `flag{` has **one** trailing zero, and the binary that outputs `02}` has **eight**. 
From here, we can assume the flag can be obtained by executing the binaries with the **least-to-most** trailing zeroes, and combining the output.

```zsh
➜ ef ** [| sha256 -t | pf {path} {0} ]] | rev | resplit [| rex '^0.*' ]] \
| sort -r | rev | resplit [| rex '[^\s]*' | run ./{0} ]] | tr '\n' ' ' | repl ' ' ''
flag{be7a1e6817d85d549f8b5abfaf18ba02}
```

After submitting the flag, we can see we were correct!

## Flag
```
flag{be7a1e6817d85d549f8b5abfaf18ba02}
```

## Notes
Initially, the challenge files included debug symbols, which included the linker timestamp along with the debug path containing which part of the flag the binary would spit out on execution. While unintended, the refinery pipeline to get the right chunks for the unintended solve was pretty neat to put together!

```zsh
➜ ef ** [| pemeta -Q | push [| rex '(flag_part[^\"].*pdb)' | pop part ] \
| push [| rex '2025\-10[^\"]*' | pop linkdate ] | run ./{path} | swap chunkedoutput \
| pf {part} {path} {linkdate} {chunkedoutput} ]] | sort | resplit \
| rex -I '.*15:46:5[56]\s(f[^9]|[bed450]).*' ]]
flag_part_0.pdb c8c5833b33584.bin 2025-10-09 15:46:55 flag{
flag_part_1.pdb 8208.bin 2025-10-09 15:46:55 be7a1
flag_part_2.pdb 7b217.bin 2025-10-09 15:46:55 e6817
flag_part_3.pdb e1204.bin 2025-10-09 15:46:55 d85d5
flag_part_4.pdb a4c71d6229e19b0.bin 2025-10-09 15:46:56 49f8b
flag_part_5.pdb 24b429c2b4f4a3c.bin 2025-10-09 15:46:56 5abfa
flag_part_6.pdb 53bc247952f.bin 2025-10-09 15:46:56 f18ba
flag_part_7.pdb c54940df1ba.bin 2025-10-09 15:46:56 02}
```
