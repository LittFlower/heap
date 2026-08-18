#define _GNU_SOURCE

/*
 * 这不是利用 PoC，只检查当前 glibc 2.32 的 _IO_file_jumps 是否位于可写映射。
 * 原版 Crust 的最终 FSOP 还需要附件专属 gadget，不能只凭这个结果判断可用。
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    /* 直接取得当前进程中的 _IO_file_jumps 地址。 */
    void *file_jumps = dlsym(RTLD_DEFAULT, "_IO_file_jumps");
    assert(file_jumps != NULL);

    /* 打开当前进程的内存映射。 */
    FILE *maps = fopen("/proc/self/maps", "r");
    assert(maps != NULL);

    char line[512];
    unsigned long start;
    unsigned long end;
    char permissions[5];

    /* 找到包含 _IO_file_jumps 的那一行。 */
    while (fgets(line, sizeof(line), maps) != NULL) {
        if (sscanf(line, "%lx-%lx %4s", &start, &end, permissions) != 3)
            continue;

        if (start <= (unsigned long)file_jumps &&
            (unsigned long)file_jumps < end)
            break;
    }

    printf("[i] file_jumps 地址=%p\n", file_jumps);
    printf("[i] 映射权限=%s\n", permissions);
    return 0;
}
