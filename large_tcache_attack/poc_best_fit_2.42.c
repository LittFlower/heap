/*
 * glibc 2.42 large tcache 的“第一个 >= 请求尺寸”行为。
 *
 * 0xa10 与 0x910 两个物理尺寸落在同一个 logarithmic large-tcache bin。
 * 2.42 的 tcache_get_large 只检查 candidate >= nb，不检查相等，因此
 * malloc(0x900) 会整块返回此前 free 的 malloc(0xa00) chunk。
 *
 * 这个行为在 glibc 2.43 被 b2b4b46 修复；不要把本文件范围扩大到 2.43。
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    (void)argc;
    setbuf(stdout, NULL);

    /* large tcache 默认关闭；glibc 只在进程启动时读取这个 tunable。 */
    if (getenv("LARGE_TCACHE_POC_READY") == NULL) {
        setenv("GLIBC_TUNABLES", "glibc.malloc.tcache_max=0x10000", 1);
        setenv("LARGE_TCACHE_POC_READY", "1", 1);
        execv(argv[0], argv);
        _exit(127);
    }

    void *large = malloc(0xa00);  /* 经过 request2size 换算后，内部 chunk size 为 0xa10。 */
    void *guard = malloc(0x30);
    assert(large != NULL && guard != NULL);
    free(large);

    void *smaller = malloc(0x900); /* request2size -> 0x910，同一个 log bin。 */

    assert(smaller == large);
    puts("[+] large tcache：best-fit 成功");

    free(smaller);
    free(guard);
    return 0;
}
