from pwn import *
#           A			B			C				D			E			F 				G			H			i 				J 			K 				L			M			 N 				O 			P 			Q				R			S			T 			 	U 			V 			W 			X 			Y   			Z			#
alpha_table = ["XO\nOO\nOO","XO\nXO\nOO","XX\nOO\nOO","XX\nOX\nOO","XO\nOX\nOO","XX\nXO\nOO","XX\nXX\nOO","XO\nXX\nOO","OX\nXO\nOO","OX\nXX\nOO","XO\nOO\nXO","XO\nXO\nXO","XX\nOO\nXO","XX\nOX\nXO","XO\nOX\nXO","XX\nXO\nXO","XX\nXX\nXO","XO\nXX\nXO","OX\nXO\nXO","OX\nXX\nXO","XO\nOO\nXX","XO\nXO\nXX","OX\nXX\nOX","XX\nOO\nXX","XX\nOX\nXX","XO\nOX\nXX","OX\nOX\nXX"]
number_table = ["XO\nOO\nOO","XO\nXO\nOO","XX\nOO\nOO","XX\nOX\nOO","XO\nOX\nOO","XX\nXO\nOO","XX\nXX\nOO","XO\nXX\nOO","OX\nXO\nOO","OX\nXX\nOO"]
				# 			1 			2			3				4			5			6			7			8				8				0
alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ#"
num = "1234567890"

#							,			;				:			.			?			!				'			
Punctuation_table_one = ["OO\nXO\nOO","OO\nXO\nXO","OO\nXX\nOO","OO\nXX\nOX","OO\nXO\nXX","OO\nXX\nXO","OO\nOO\nXO"]
Punctuation_one = ",;:.?!'"
Punctuation_two = '"()/\\'
Punctuation_table_two= [["OO\nOO\nXO","OO\nXX\nXX"],["OO\nOX\nOO","XO\nXO\nOX"]  ,["OO\nOX\nOO","OX\nOX\nXO"] ,["OX\nOX\nOX","OX\nOO\nXO"],["OX\nOX\nOX","XO\nOO\nOX"]] 
#								" 							(							)							/						\


def solve_alpha_and_Punctuation(one_line,two_line,three_line):

	one_line = one_line.replace("\n","").split(" ")
	two_line = two_line.replace("\n","").split(" ")
	three_line = three_line.replace("\n","").split(" ")

	P_one_ = []
	P_one_cnt=[]
	result = [i for i in "\x00"*100]

	alpha_cnt = []
	alpha_arr_ = []
	#first two
	i=0
	cnnt = 0
	while True:
		chk_in = False
		if(i>= len(three_line)-1):
			break

		tmp  = one_line[i] + one_line[i+1] + "\n"
		tmp += two_line[i] + two_line[i+1] + "\n"
		tmp += three_line[i] + three_line[i+1] 

		for j in range(len(Punctuation_table_two)):
			pun_tmp = Punctuation_table_two[j][0].split("\n")
			pun_tmp1 =Punctuation_table_two[j][1].split("\n")
			cmp_value = pun_tmp[0] + pun_tmp1[0] + "\n"+ pun_tmp[1] + pun_tmp1[1] + "\n"+ pun_tmp[2] + pun_tmp1[2]
			if(cmp_value==tmp):
				#print result[cnnt]
				result[cnnt]= Punctuation_two[j]
				chk_in=True
				break

		if(not chk_in): #mov one
			P_one_.append(i)
			P_one_cnt.append(cnnt)
			i+=1
		else:	
			i+=2
		cnnt +=1
	if(i == len(three_line)-1):
		P_one_.append(i)
		P_one_cnt.append(cnnt)

	for i in range(0,len(P_one_)):
		chk_in=False
		tmp  = one_line[P_one_[i]]  + "\n"
		tmp += two_line[P_one_[i]]  + "\n"
		tmp += three_line[P_one_[i]] 
		for j in range(0,len(Punctuation_table_one)):
			if(Punctuation_table_one[j] == tmp):
				result[P_one_cnt[i]] += Punctuation_one[j]
				chk_in=True
				break
		if not chk_in:
			alpha_arr_.append(P_one_[i])
			alpha_cnt.append(P_one_cnt[i])


		for i in range(0,len(alpha_arr_)):

			tmp = one_line[alpha_arr_[i]] + "\n"
			tmp += two_line[alpha_arr_[i]] + "\n"
			tmp += three_line[alpha_arr_[i]]
			for j in range(0,len(alpha_table)): # chk alphabet
				if(tmp == alpha_table[j]):
					result[alpha_cnt[i]] = alpha[j]

	return ''.join(result).replace("\x00","")

def solve_Punctuation(one_line,two_line,three_line):
	try:
		one_line = one_line.replace("\n","").split(" ")
		two_line = two_line.replace("\n","").split(" ")
		three_line = three_line.replace("\n","").split(" ")
	except:
		None

	if(one_line[len(one_line)-1] == ""):
		one_line.pop()
	if(two_line[len(two_line)-1] == ""):
		two_line.pop()
	if(three_line[len(three_line)-1] == ""):
		three_line.pop()
	
	
	P_one_ = []
	P_one_cnt=[]
	result = [i for i in "\x00"*50]
	#first two
	i=0
	cnnt = 0
	while True:
		chk_in = False
		if(i>= len(three_line)-1):
			break

		tmp  = one_line[i] + one_line[i+1] + "\n"
		tmp += two_line[i] + two_line[i+1] + "\n"
		tmp += three_line[i] + three_line[i+1] 

		for j in range(len(Punctuation_table_two)):
			pun_tmp = Punctuation_table_two[j][0].split("\n")
			pun_tmp1 =Punctuation_table_two[j][1].split("\n")
			cmp_value = pun_tmp[0] + pun_tmp1[0] + "\n"+ pun_tmp[1] + pun_tmp1[1] + "\n"+ pun_tmp[2] + pun_tmp1[2]
			if(cmp_value==tmp):
				#print result[cnnt]
				result[cnnt]= Punctuation_two[j]
				chk_in=True
				break

		if(not chk_in): #mov one
			P_one_.append(i)
			P_one_cnt.append(cnnt)
			i+=1
		else:	
			i+=2
		cnnt +=1
	if(i == len(three_line)-1):
		P_one_.append(i)
		P_one_cnt.append(cnnt)


	for i in range(0,len(P_one_)):
		tmp  = one_line[P_one_[i]]  + "\n"
		tmp += two_line[P_one_[i]]  + "\n"
		tmp += three_line[P_one_[i]] 
		for j in range(0,len(Punctuation_table_one)):
			if(Punctuation_table_one[j] == tmp):
				result[P_one_cnt[i]] += Punctuation_one[j]
				break

	return ''.join(result).replace("\x00","")


		


def solve_num_or_table(one_line,two_line,three_line,num_or_table):
	one_line = one_line.replace("\n","").split(" ")
	two_line = two_line.replace("\n","").split(" ")
	three_line = three_line.replace("\n","").split(" ")
	result = ""

	for i in range(0,len(three_line)):

		tmp = one_line[i] + "\n"
		tmp += two_line[i] + "\n"
		tmp += three_line[i]

		#print tmp+"\n"
		#print tmp
		if(num_or_table == 1):
			for j in range(0,len(alpha_table)): # chk alphabet
				if(tmp == alpha_table[j]):
					result += alpha[j]
		else:
				for j in range(0,len(number_table)):
					if(tmp == number_table[j]):
						result += num[j]
						chk_in =True

	return result


p = remote("112.166.114.150",49374)


for i in range(0,41):
	p.recvuntil("=\n")
	req = 0
	a = p.recvline()
	print a
	if "NUMBER" in a:
		req = 0
	elif "WORD" in a or "WARM" in a:
		req = 1
	elif 21<=i  and i<=30:
		req = 3
	else:
		req=4
	if(req <= 1):
		answer = solve_num_or_table(p.recvline(),p.recvline(),p.recvline(),req)

	elif(req==3):
		if(i==21):
			p.recvuntil("Brailles.\n\n")
		answer=solve_Punctuation(p.recvline(),p.recvline(),p.recvline())

	elif(req==4):
		answer=solve_alpha_and_Punctuation(p.recvline(),p.recvline(),p.recvline())

	p.sendline(answer)
	print "TRY : " + str(i) + "  VALUE : " + str(answer)



p.interactive()