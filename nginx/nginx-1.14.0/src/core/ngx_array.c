
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/** 
 ´´½¨Ò»¸öÊý×é£¬
 pÊÇÄÚ´æ³Ø¶ÔÏó£¬ 
 nÎªÊý×é´æ´¢ÔªËØµÄ¸öÊý£¬
 sizeÎªÃ¿¸öÔªËØÕ¼ÓÃµÄ¿Õ¼ä´óÐ¡¡ 
 */
ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;
    /*1: ÔÚÄÚ´æ³Ø poolÉÏÃæ ·ÖÅäÒ»¶ÎÄÚ´æ¸ø ngx_arrayÊý¾Ý½á¹¹*/ 
    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }
    /*2£ºÉêÇëÊý×é´æ´¢ÔªËØµÄÄÚ´æ*/
    if (ngx_array_init(a, p, n, size) != NGX_OK) {
        return NULL;
    }

    return a;
}

/** 
 * Êý×éÏú»Ù 
 * Êý×éÏú»ÙÉè¼ÆµÄÒ²Í¦½²¾¿µÄ£¬»áÈ¥°ïÖúÇå³ýÄÚ´æ³ØÉÏµÄÄÚ´æ 
 */ 
void
ngx_array_destroy(ngx_array_t *a)
{
    ngx_pool_t  *p;

    p = a->pool;
    /*1£ºÏú»ÙÊý×é´æ´¢ÔªËØµÄÄÚ´æ£¬¼´Êý¾ÝÇøµÄÄÚ´æ*/
    if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
        p->d.last -= a->size * a->nalloc;
    }
    /*2£ºÏú»ÙÊý×é±¾ÉíµÄÄÚ´æ£¬¼´½á¹¹Ìåarray±¾ÉíµÄÄÚ´æ */
    if ((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }
}

/** 
 * Ìí¼ÓÒ»¸öÔªËØ 
 */ 
void *
ngx_array_push(ngx_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    ngx_pool_t  *p;
/* Èç¹ûÊý×éÖÐÔªËØ¶¼ÓÃÍêÁË £¬ÔòÐèÒª¶ÔÊý×é½øÐÐÀ©ÈÝ */ 
    if (a->nelts == a->nalloc) {

        /* the array is full */

        size = a->size * a->nalloc;

        p = a->pool;
         /** 
         * À©ÈÝÓÐÁ½ÖÖ·½Ê½ 
         * 1.Èç¹ûÊý×éÔªËØµÄÄ©Î²ºÍÄÚ´æ³ØpoolµÄ¿ÉÓÃ¿ªÊ¼µÄµØÖ·ÏàÍ¬£¬ 
         * ²¢ÇÒÄÚ´æ³ØÊ£ÓàµÄ¿Õ¼äÖ§³ÖÊý×éÀ©ÈÝ£¬ÔòÔÚµ±Ç°ÄÚ´æ³ØÉÏÀ©ÈÝ 
         * 2. Èç¹ûÀ©ÈÝµÄ´óÐ¡³¬³öÁËµ±Ç°ÄÚ´æ³ØÊ£ÓàµÄÈÝÁ¿»òÕßÊý×éÔªËØµÄÄ©Î²ºÍÄÚ´æ³ØpoolµÄ¿ÉÓÃ¿ªÊ¼µÄµØÖ·²»ÏàÍ¬£¬ 
         * ÔòÐèÒªÖØÐÂ·ÖÅäÒ»¸öÐÂµÄÄÚ´æ¿é´æ´¢Êý×é£¬²¢ÇÒ½«Ô­Êý×é¿½±´µ½ÐÂµÄµØÖ·ÉÏ 
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
 * Õâ¸ö·½·¨Í¬ÉÏ£¬Ö»²»¹ýÖ§³Ö¶à¸öÔªËØ 
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
