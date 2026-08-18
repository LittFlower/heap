/*
 * glibc 2.43 large tcache 的精确尺寸匹配。
 *
 * 排布与 poc_best_fit_2.42.c 相同：0xa10 和 0x910 仍落在同一个
 * logarithmic bin，但 tcache_get_large 现在额外检查
 *     nb == chunksize(candidate)
 * 所以 malloc(0x900) 不能消费 0xa10 chunk；随后 malloc(0xa00) 才能取回它。
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

    void *large = malloc(0xa00);  /* 物理尺寸 0xa10。 */
    void *guard = malloc(0x30);
    assert(large != NULL && guard != NULL);
    free(large);

    void *smaller = malloc(0x900); /* 物理尺寸 0x910：同 log bin，但不相等。 */

    assert(smaller != large);

    void *exact = malloc(0xa00);

    assert(exact == large);
    puts("[+] large tcache：精确匹配成功");

    free(smaller);
    free(exact);
    free(guard);
    return 0;
}
