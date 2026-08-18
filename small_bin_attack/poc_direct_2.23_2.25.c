/*
 * “small bin attack”检索入口：direct smallbin / House of Lore，2.23～2.25。
 * 被包含的权威实现使用两组自洽 fake chunk，并严格断言 malloc 返回栈地址。
 */
#include "../house_of_lore/poc_2.23_2.25.c"
