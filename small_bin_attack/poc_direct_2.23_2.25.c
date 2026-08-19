/*
 * 本文件是“small bin attack”手法在 direct smallbin / House of Lore 分支
 * （2.23～2.25）下的检索入口。被包含的权威实现用两组互相自洽的 fake
 * chunk 搭建攻击链，并通过严格的断言确认 malloc 最终返回的确实是栈地址。
 */
#include "../house_of_lore/poc_2.23_2.25.c"
