/*
 * “small bin attack”检索入口：glibc 2.43 direct smallbin / House of Lore。
 * 该分支按默认 16-slot tcache 重排；详细中文说明和成功判据见包含的实现。
 */
#include "../house_of_lore/poc_2.43.c"
