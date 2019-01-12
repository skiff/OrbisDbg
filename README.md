# OrbisDbg
Source code for the PS4 payload and c++ library to be used for tools. <br>
This payload only supports PS4 systems on 5.05

# Features
- Memory Read/Write
- Get Process List
- Attach/Detach Process
- Continue Process
- Signal Process (Pause, Kill etc)
- Get/Set Registers
- Get Process Flags
- ELF Loading
- Kernel Reboot

# How to Use
1. Download OrbisDbgUI or any other debugger using this payload
2. Send OrbisDbg.bin to your console
3. Launch and attach to game process
4. Debug

# Information
- The Makefile will build both the kernel level elf as well as the payload that loads it. The ELF folder contains the code for the debugger code and the Payload folder contains the code for the loader. The DLL source is just a C# wrapper for connecting between a tool and the PS4 system.

# Credits
[Sabotage](https://github.com/egatobaS) for his 4.55 debugger and tons of help on this project<br>
[Golden/Xemio] (https://github.com/xemio) for 5.05 patches/kernel offsets and process elf loading<br>
[Vortex] (https://github.com/xvortex) for his version of ps4 payload sdk for base webkit payloads<br>
[CTurt] (https://github.com/CTurt) original ps4 payload sdk<br>
[Specter] (https://github.com/Cryptogenic) 5.05 exploit<br>
[2much4u] (https://github.com/2much4u)<br>
Anyone else who has contributed to PS4 exploit<br>