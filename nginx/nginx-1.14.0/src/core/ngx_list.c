
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
/*���������
https://blog.csdn.net/livelylittlefish/article/details/6599065


*/

/*����һ�������������г�ʼ��*/
ngx_list_t *
ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    ngx_list_t  *list;
    /*���ڴ���з�������ͷ���ngx_list_t*/
    list = ngx_palloc(pool, sizeof(ngx_list_t));
    if (list == NULL) {
        return NULL;
    }
    /*����n*size�����������������ͷ���г�ʼ��*/
    if (ngx_list_init(list, pool, n, size) != NGX_OK) {
        return NULL;
    }

    /*��������ͷ����ʼλ��*/
    return list;
}

/*�����ڸ������������з���Ԫ��(Ԫ�ؿ�����1������)��λ��*/
void *
ngx_list_push(ngx_list_t *l)
{
    void             *elt;
    ngx_list_part_t  *last;

    last = l->last;
    /*��ǰ����ڵ������������*/
    if (last->nelts == l->nalloc) {

        /* the last part is full, allocate a new list part */
       /*���ڴ��������ڵ�ṹ���С*/
        last = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
        if (last == NULL) {
            return NULL;
        }
        /*���ڴ����Ϊ��ǰ�ڵ�����������*/
        last->elts = ngx_palloc(l->pool, l->nalloc * l->size);
        if (last->elts == NULL) {
            return NULL;
        }
        /*��ǰ�ڵ���ʹ�ø����ݣ����ڵ�nextָ�븳ֵ*/
        last->nelts = 0;
        last->next = NULL;
        /*����ͷ�ṹ��ֵ*/
        l->last->next = last;
        l->last = last;
    }
    /*������һ������λ��*/
    elt = (char *) last->elts + l->size * last->nelts;
    last->nelts++;/*��������Ÿ���+1*/

    return elt;
}
