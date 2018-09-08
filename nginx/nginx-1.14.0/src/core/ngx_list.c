
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
/*单链表分析
https://blog.csdn.net/livelylittlefish/article/details/6599065


*/

/*创建一个单链表，并进行初始化*/
ngx_list_t *
ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    ngx_list_t  *list;
    /*从内存池中分配链表头结点ngx_list_t*/
    list = ngx_palloc(pool, sizeof(ngx_list_t));
    if (list == NULL) {
        return NULL;
    }
    /*分配n*size数据区，并对链表表头进行初始化*/
    if (ngx_list_init(list, pool, n, size) != NGX_OK) {
        return NULL;
    }

    /*返回链表头的起始位置*/
    return list;
}

/*可以在该链表数据区中放置元素(元素可以是1个或多个)的位置*/
void *
ngx_list_push(ngx_list_t *l)
{
    void             *elt;
    ngx_list_part_t  *last;

    last = l->last;
    /*当前链表节点的数据区已满*/
    if (last->nelts == l->nalloc) {

        /* the last part is full, allocate a new list part */
       /*从内存池上申请节点结构体大小*/
        last = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
        if (last == NULL) {
            return NULL;
        }
        /*从内存池上为当前节点申请数据区*/
        last->elts = ngx_palloc(l->pool, l->nalloc * l->size);
        if (last->elts == NULL) {
            return NULL;
        }
        /*当前节点已使用个数据，及节点next指针赋值*/
        last->nelts = 0;
        last->next = NULL;
        /*链表头结构赋值*/
        l->last->next = last;
        l->last = last;
    }
    /*计算下一数据区位置*/
    elt = (char *) last->elts + l->size * last->nelts;
    last->nelts++;/*数据区存放个数+1*/

    return elt;
}
