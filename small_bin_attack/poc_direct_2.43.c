/*
 * 本文件是“small bin attack”手法在 glibc 2.43 下 direct smallbin /
 * House of Lore 分支的检索入口。这个版本按默认的 16-slot tcache 重排做
 * 了适配；详细的中文说明和成功判据都写在被包含的实现文件里。
 */
#include "../house_of_lore/poc_2.43.c"
