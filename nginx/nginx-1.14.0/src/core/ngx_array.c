
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/** 
 ����һ�����飬
 p���ڴ�ض��� 
 nΪ����洢Ԫ�صĸ�����
 sizeΪÿ��Ԫ��ռ�õĿռ��С� 
 */
ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;
    /*1: ���ڴ�� pool���� ����һ���ڴ�� ngx_array���ݽṹ*/ 
    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }
    /*2����������洢Ԫ�ص��ڴ�*/
    if (ngx_array_init(a, p, n, size) != NGX_OK) {
        return NULL;
    }

    return a;
}

/** 
 * �������� 
 * ����������Ƶ�Ҳͦ�����ģ���ȥ��������ڴ���ϵ��ڴ� 
 */ 
void
ngx_array_destroy(ngx_array_t *a)
{
    ngx_pool_t  *p;

    p = a->pool;
    /*1����������洢Ԫ�ص��ڴ棬�����������ڴ�*/
    if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
        p->d.last -= a->size * a->nalloc;
    }
    /*2���������鱾����ڴ棬���ṹ��array������ڴ� */
    if ((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }
}

/** 
 * ���һ��Ԫ�� 
 */ 
void *
ngx_array_push(ngx_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    ngx_pool_t  *p;
/* ���������Ԫ�ض������� ������Ҫ������������� */ 
    if (a->nelts == a->nalloc) {

        /* the array is full */

        size = a->size * a->nalloc;

        p = a->pool;
         /** 
         * ���������ַ�ʽ 
         * 1.�������Ԫ�ص�ĩβ���ڴ��pool�Ŀ��ÿ�ʼ�ĵ�ַ��ͬ�� 
         * �����ڴ��ʣ��Ŀռ�֧���������ݣ����ڵ�ǰ�ڴ�������� 
         * 2. ������ݵĴ�С�����˵�ǰ�ڴ��ʣ���������������Ԫ�ص�ĩβ���ڴ��pool�Ŀ��ÿ�ʼ�ĵ�ַ����ͬ�� 
         * ����Ҫ���·���һ���µ��ڴ��洢���飬���ҽ�ԭ���鿽�����µĵ�ַ�� 
         */ 
        if ((u_char *) a->elts + size == p->d.last
            && p->d.last + a->size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += a->size;
            a->nalloc++;

        } else {
            /* allocate a new array */

            new = ngx_palloc(p, 2 * size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, size);
            a->elts = new;
            a->nalloc *= 2;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts++;

    return elt;
}

/** 
 * �������ͬ�ϣ�ֻ����֧�ֶ��Ԫ�� 
 */
void *
ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void        *elt, *new;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *p;

    size = n * a->size;

    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

        if ((u_char *) a->elts + a->size * a->nalloc == p->d.last
            && p->d.last + size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;
            a->nalloc += n;

        } else {
            /* allocate a new array */

            nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

            new = ngx_palloc(p, nalloc * a->size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, a->nelts * a->size);
            a->elts = new;
            a->nalloc = nalloc;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}
