from z3 import *
from pwn import hexdump
import subprocess
import time

FILENAME = None
passcode = []
stage = len(passcode) / 4


def getcalcfunctions() :
    get = subprocess.check_output("mips-linux-gnu-objdump -d ./{0}".format(FILENAME),shell=True)
    result = []
    addr = 0
    for line in map(str.strip,get.split("\n")) : 
        if "jr\tra" in line :
            tmp = int(line.split(":")[0],16)
            result.append([addr,tmp-addr])
        if "addiu\tsp,sp,-" in line : 
            addr = int(line.split(":")[0],16)
    
    return result[4:-12]


def getfunctiondisassembly(startaddress) : 
    get = subprocess.check_output("mips-linux-gnu-objdump -d ./{0} --start-address={1}".format(FILENAME,hex(startaddress)),shell=True)
    get = map(str.strip,get.split("\n"))
    for i in range(len(get)) : 
        if "jr\tra" in get[i] : 
            return get[6:i]


class Parser : 
    def __init__(self,func) :
        self.disasmfunc = getfunctiondisassembly(func[0])

    def parseasm(self,instGoal) : 
        result = []

        for line in self.disasmfunc : 
            if len(line.split("\t")) < 2 : continue
            inst = line.split("\t")[2]

            if len(line.split("\t")) > 3 : 
                inst2 = line.split("\t")[3]
                parts = map(str.strip,inst2.split(","))

            if inst.startswith(instGoal) :
                result.append([inst]+parts)

            lwchk = False

        return result

    def parseidx(self) : 
        lwchk = False

        result = []

        for line in self.disasmfunc : 
            if len(line.split("\t")) < 2 : continue

            inst = line.split("\t")[2]

            if len(line.split("\t")) > 3 : 
                inst2 = line.split("\t")[3]
                parts = map(str.strip,inst2.split(","))

            if inst == "lw": 
                lwchk = True
                continue

            if inst == "addiu" and lwchk :
                try : 
                    num = int(parts[2])
                    if num >= 4 :
                        continue
                    result += [num]
                except : 
                    continue

            elif inst == "lbu" and lwchk:
                result += [0]

            lwchk = False

        return result  

def stage660_parse(func) : 
    result = []
    conditions = []

    parser = Parser(func)
    bjump = parser.parseasm("b")

    for i in [bjump[2],bjump[5]] : 
        cond = ""
        if "beq" in i[0] : cond = "LT"
        elif "bne" in i[0] : cond = "LE"
        if cond == "" :
            print(cond + " is not supported")
            exit(1)
        conditions.append(cond)

    final = []

    for i in parser.parseidx()[:8] : 
        if i not in final :
            final.append(i)
        
    return final ,conditions


def newSolver() : 
    pbParm1 = []
    s = Solver()

    for i in range(4) : 
        pbParm1.append(BitVec("a"+str(i),32))
        s.add(pbParm1[i] <= 0xff)
        s.add(pbParm1[i] >= 0)
    
    return s , pbParm1

def getResult(s,pbParm1) :
    s.check()
    m = s.model()
    result = []

    for i in range(4) : 
        result.append(int(str(m.evaluate(pbParm1[i]))))
    
    return result

def stage660(idxs,conditions) : 
    s,pbParm1 = newSolver()

    iVar1 = pbParm1[idxs[0]] * pbParm1[idxs[0]] - pbParm1[idxs[1]] * pbParm1[idxs[1]]
    iVar1 = If(iVar1 < 0 , -iVar1 , iVar1)

    iVar2 = pbParm1[idxs[2]] * pbParm1[idxs[2]] - pbParm1[idxs[3]] * pbParm1[idxs[3]]
    iVar2 = If(iVar2 < 0 , -iVar2 , iVar2)

    if conditions[0] == "LT" :
        s.add(iVar1 < iVar2)
    elif conditions[0] == "LE" :
        s.add(iVar2 <= iVar1)

    iVar3 = pbParm1[idxs[2]] * pbParm1[idxs[2]] - pbParm1[idxs[0]] * pbParm1[idxs[0]];
    iVar3 = If(iVar3 < 0 , -iVar3 , iVar3)

    iVar4 = pbParm1[idxs[3]] * pbParm1[idxs[3]] - pbParm1[idxs[1]] * pbParm1[idxs[1]];
    iVar4 = If(iVar4 < 0 , -iVar4 , iVar4)

    if conditions[1] == "LT" :
        s.add(iVar3 < iVar4)
    elif conditions[1] == "LE" :
        s.add(iVar4 <= iVar3)

    return getResult(s,pbParm1)


def stage312(func) : 
    parser = Parser(func)
    idxs = parser.parseidx()
    values = parser.parseasm("li")

    s,pbParm1 = newSolver()

    s.add(pbParm1[idxs[0]] == int(values[0][2]))
    s.add(pbParm1[idxs[1]] == int(values[1][2]))
    s.add(pbParm1[idxs[2]] == (pbParm1[idxs[3]] * pbParm1[idxs[4]])&0xff)
    s.add(pbParm1[idxs[5]] == ((pbParm1[idxs[6]] * pbParm1[idxs[7]] + pbParm1[idxs[8]] * pbParm1[idxs[9]]) - pbParm1[idxs[10]] * pbParm1[idxs[11]])&0xff)

    return getResult(s,pbParm1)

def stage328(func) : 
    parser = Parser(func)
    idxs = parser.parseidx()
    values = parser.parseasm("li")

    s,pbParm1 = newSolver()

    s.add(pbParm1[idxs[0]]+pbParm1[idxs[1]]+pbParm1[idxs[2]] == int(values[0][2]))
    s.add(pbParm1[idxs[3]]+pbParm1[idxs[4]]+pbParm1[idxs[5]] == int(values[1][2]))
    s.add(pbParm1[idxs[6]]+pbParm1[idxs[7]]+pbParm1[idxs[8]] == int(values[2][2]))
    s.add(pbParm1[idxs[9]]+pbParm1[idxs[10]]+pbParm1[idxs[11]] == int(values[3][2]))

    return getResult(s,pbParm1)

def stage288(func) : 
    parser = Parser(func)
    idxs = parser.parseidx()
    values = parser.parseasm("li")
    
    s,pbParm1 = newSolver()

    s.add(pbParm1[idxs[0]]^pbParm1[idxs[1]] == int(values[0][2]))
    s.add(pbParm1[idxs[2]] == int(values[1][2]))
    s.add(pbParm1[idxs[3]] == ((pbParm1[idxs[4]]^pbParm1[idxs[5]])&0x7f) << 1)
    s.add(pbParm1[idxs[6]] == pbParm1[idxs[7]]^pbParm1[idxs[8]]^pbParm1[idxs[9]])

    return getResult(s,pbParm1)

def stage224(func) : 
    parser = Parser(func)
    idxs = parser.parseidx()
    values = parser.parseasm("li")

    s,pbParm1 = newSolver()

    s.add(pbParm1[idxs[0]]+pbParm1[idxs[1]] != int(values[0][2]))
    s.add(pbParm1[idxs[2]]+pbParm1[idxs[3]] != int(values[1][2]))
    s.add(pbParm1[idxs[4]]+pbParm1[idxs[5]] != int(values[2][2]))

    return getResult(s,pbParm1)

def stage208(func) : 
    parser = Parser(func)
    idxs = parser.parseidx()
    values = parser.parseasm("li")

    s,pbParm1 = newSolver()

    s.add(pbParm1[idxs[0]] == pbParm1[idxs[1]])
    s.add(pbParm1[idxs[2]] == pbParm1[idxs[3]])
    s.add(pbParm1[idxs[4]] == int(values[0][2]))
    s.add(pbParm1[idxs[5]] == int(values[1][2]))

    return getResult(s,pbParm1)


def run(functions) :
    global passcode
    global stage
    start = time.time() 
    for func in functions[stage+1:] :      
        if(functions[stage][1] > 430) : 
            idxs,condition = stage660_parse(functions[stage])
            passcode += stage660(idxs,condition)
                  
        elif(functions[stage][1] >= 304 and functions[stage][1] <= 320) : 
            passcode += stage312(functions[stage])
                  
        elif functions[stage][1] == 296 :
            passcode += stage328(functions[stage])
            
        elif(functions[stage][1] >= 252 and functions[stage][1] <= 270) : 
            passcode += stage288(functions[stage])
                  
        elif(functions[stage][1] >= 190 and functions[stage][1] <= 228) : 
            passcode += stage224(functions[stage])
            
        elif(functions[stage][1] >= 170) :
            passcode += stage208(functions[stage])
        
    
        stage += 1
    

def getpasscode(filename) : 
    global FILENAME
    FILENAME = filename
    stages = getcalcfunctions()[::-1]
    run(stages)
    return passcode
