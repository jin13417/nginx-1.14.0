
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
/*Nginx��buf���������ݽṹ����Ҫ�����洢�ǳ������ڴ�
�ngx_buf_t���ݽṹҲ�ᴩ������Nginx��Nginx�Ļ���������ǱȽ����ġ�
1. �����Զ������ҵ�����Ļ���������
2. Ҳ���Խ����еĻ��������������ڴ��pool->chain�ṹ��
������ngx_buf_t��nginx��������ݵĹؼ����ݽṹ������Ӧ�����ڴ�����
ҲӦ���ڴ�������*/

ngx_buf_t *
ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t *b;

   /*���ڴ��������ngx_buf_t�ṹ���ڴ棬�����г�ʼ��*/
    b = ngx_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }
    /*���ڴ��������size��С�Ļ������������г�ʼ��*/
    b->start = ngx_palloc(pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    /*
     * set by ngx_calloc_buf():
     *
     *     b->file_pos = 0;
     *     b->file_last = 0;
     *     b->file = NULL;
     *     b->shadow = NULL;
     *     b->tag = 0;
     *     and flags
     */
    
    b->pos = b->start; /*�����������Ŀ�ʼ*/
    b->last = b->start;/*�����������Ľ�β*/
    b->end = b->last + size; /*��������β*/
    b->temporary = 1;   /*��ʾ����������ȥ���Ա��޸�*/

    return b;
}

/*����һ������������ṹ
1�����ڴ�ػ����������л�ȡ
2������ڴ�ȥ�����������޿��ã�ֱ�����ڴ��������
*/
ngx_chain_t *
ngx_alloc_chain_link(ngx_pool_t *pool)
{
    ngx_chain_t  *cl;

    cl = pool->chain;
    /* 
     * ���ȴ��ڴ����ȥȡngx_chain_t�� 
     * ����յ�ngx_chain_t�ṹ�������pool->chain �������� 
     */ 
    if (cl) {
        pool->chain = cl->next;
        return cl;
    }
    /* ���ȡ����������ڴ��pool�Ϸ���һ�����ݽṹ  */
    cl = ngx_palloc(pool, sizeof(ngx_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}

/** 
 * �����������buf��������ngx_chain_t������������������ͷ 
 */ 
ngx_chain_t *
ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs)
{
    u_char       *p;
    ngx_int_t     i;
    ngx_buf_t    *b;
    ngx_chain_t  *chain, *cl, **ll;
    /* ���ڴ��pool�Ϸ���bufs->num�� buf������ ��ÿ����СΪbufs->size */
    p = ngx_palloc(pool, bufs->num * bufs->size);
    if (p == NULL) {
        return NULL;
    }
    /*ָ�򻺴���ͷ�ڵ�*/
    ll = &chain;
    /* ѭ������ngx_buf_t�����ҽ�ngx_buf_t���ص�ngx_chain_t�����ϣ����ҷ�������*/ 
    for (i = 0; i < bufs->num; i++) {
        /* ���յ��õ����ڴ��pool����Ҫ����ngx_buf_t�ṹ���ַ */
        b = ngx_calloc_buf(pool);
        if (b == NULL) {
            return NULL;
        }

        /*
         * set by ngx_calloc_buf():
         *
         *     b->file_pos = 0;
         *     b->file_last = 0;
         *     b->file = NULL;
         *     b->shadow = NULL;
         *     b->tag = 0;
         *     and flags
         *
         */
        /*ngx_buf_t �ṹ���ʼ����������*/
        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        p += bufs->size;
        b->end = p;
       /*�ڴ��������ngx_chain_t�������ڹҽӻ�����*/
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;
        *ll = cl;
        ll = &cl->next;
    }
    /*ngx_chain_t���������һ���ÿ�*/
    *ll = NULL;

    return chain;
}

/*
*pool �ڴ��ָ�룬��Ҫ��������ngx_chain_t�ṹ���ַ
*chain Ŀ��ngx_chain_t �����ͷ��ַ�������ʹ�ö���ָ�����*chain =NULL,�������
*in      Դngx_chain_t �����ͷ��ַ��
*������Ҫ�����ǽ�Դngx_chain_t *in�����ϵ�����copy��Ŀ��ngx_chain_t ������
*/
ngx_int_t
ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;

    ll = chain;

    /*�ҵ�chain��������������һ���ڵ㣬�������һ���ڵ�
	�ĵ�ַ��ֵ ll */
    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

   /* ����in ������in�����ϵĽڵ㻺�����ṹ��copy��chain������*/ 
    while (in) {
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = in->buf;
        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }
    /*Ŀ��ngx_chain_t �����ϵ����һ���ڵ��ÿ�*/
    *ll = NULL;

    return NGX_OK;
}

/** 
 * �ӿ��е�ngx_chain_t�����ϣ���ȡһ��δʹ�õ�ngx_chain_t�ڵ�
 *1�����free �������п��нڵ㣬ֱ�ӷ��ؿ��нڵ�ָ�룻
 *2������޿��нڵ㣬���ڴ��������ngx_chain_t��ngx_buf_t���ڵ㣬
 */ 
ngx_chain_t *
ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free)
{
    ngx_chain_t  *cl;
    /*1�����free �������п��нڵ㣬ֱ�ӷ��ؿ��нڵ�ָ�룻*/
    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;
        return cl;
    }
    /*2������޿��нڵ㣬���ڴ��������ngx_chain_t��ngx_buf_t���ڵ㣬*/
    cl = ngx_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ngx_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    return cl;
}

/** 
 * �ͷ�BUF 
 * 1. ���buf��Ϊ�գ����ͷ� 
 * 2. ���cl->buf->tag��ǲ�һ������ֱ�ӻ���Nginx��pool->chain���� 
 * 3. ���bufΪ�գ�������Ҫ�ͷţ���ֱ���ͷ�buf�����ҷŵ�free�Ŀ����б��� 
 */
void
ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free, ngx_chain_t **busy,
    ngx_chain_t **out, ngx_buf_tag_t tag)
{
    ngx_chain_t  *cl;

   /*���out��Ϊ�գ���out�ҽӵ�busy�����ϣ�
      ����out�ÿ�*/
    if (*out) {
       /*1 ���busyΪ�գ�outֱ�Ӹ�ֵ��busy*/
        if (*busy == NULL) {
            *busy = *out;

        } else {
           /*busy ��Ϊ�գ���out�ҽӵ�busy����������*/
            for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

            cl->next = *out;
        }

        *out = NULL;
    }
    /*����busy����*/
    while (*busy) {
        cl = *busy;
        /*1 ���������ݲ�Ϊ0ʱ��ֱ�ӷ���*/
        if (ngx_buf_size(cl->buf) != 0) {
            break;
        }
        /*2 ģ���ʶ��һ��ʱ������ǰ�ڵ��busy����������
		���ҽӵ��ڴ�ص������ϡ�*/
        if (cl->buf->tag != tag) {
            *busy = cl->next;
            ngx_free_chain(p, cl);
            continue;
        }
        /*3 ����ǰbusy�����ϵĽڵ�����������ÿ�*/
        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

	/*4 ��������ǰ�ڵ�ҽӵ�free������ȥ*/
        *busy = cl->next;
        cl->next = *free;
        *free = cl;
    }
}

/*�����ļ����ͣ������������ݴ�СΪlimit*/
off_t
ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit)
{
    off_t         total, size, aligned, fprev;
    ngx_fd_t      fd;
    ngx_chain_t  *cl;

    total = 0;

    cl = *in;
    fd = cl->buf->file->fd;

    do {
        size = cl->buf->file_last - cl->buf->file_pos;

        if (size > limit - total) {
            size = limit - total;

            aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)
                       & ~((off_t) ngx_pagesize - 1);

            if (aligned <= cl->buf->file_last) {
                size = aligned - cl->buf->file_pos;
            }

            total += size;
            break;
        }

        total += size;
        fprev = cl->buf->file_pos + size;
        cl = cl->next;

    } while (cl
             && cl->buf->in_file
             && total < limit
             && fd == cl->buf->file->fd
             && fprev == cl->buf->file_pos);

    *in = cl;

    return total;
}

/*����in������������,������ļ���*/
ngx_chain_t *
ngx_chain_update_sent(ngx_chain_t *in, off_t sent)
{
    off_t  size;

    for ( /* void */ ; in; in = in->next) {
       /*����ڵ������⻺�����Ͳ�����*/
        if (ngx_buf_special(in->buf)) {
            continue;
        }

        if (sent == 0) {
            break;
        }
	 /*��ȡ��ǰ���������������ݵĴ�С*/
        size = ngx_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;
	    /*���������ݻ�������գ���pos = last*/
            if (ngx_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;
            }
	     /*���Ӧ����dead core��ǰ�����жϷ��ļ�����*/
            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last;
            }

            continue;
        }

	/*�����*/
        if (ngx_buf_in_memory(in->buf)) {
            in->buf->pos += (size_t) sent;
        }

        /*���Ӧ����dead core��ǰ�����жϷ��ļ�����*/
        if (in->buf->in_file) {
            in->buf->file_pos += sent;
        }

        break;
    }

    return in;
}
