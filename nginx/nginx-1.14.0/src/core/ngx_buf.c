
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
/*Nginx的buf缓冲区数据结构，主要用来存储非常大块的内存�
gx_buf_t数据结构也贯穿了整个Nginx。Nginx的缓冲区设计是比较灵活的。
1. 可以自定义管理业务层面的缓冲区链表；
2. 也可以将空闲的缓冲区链表交还给内存池pool->chain结构。
缓冲区ngx_buf_t是nginx处理大数据的关键数据结构，它既应用于内存数据
也应用于磁盘数据*/

ngx_buf_t *
ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t *b;

   /*在内存池上申请ngx_buf_t结构体内存，并进行初始化*/
    b = ngx_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }
    /*在内存池上申请size大小的缓存区，并进行初始化*/
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
    
    b->pos = b->start; /*待处理缓存器的开始*/
    b->last = b->start;/*待处理缓存器的结尾*/
    b->end = b->last + size; /*缓存区结尾*/
    b->temporary = 1;   /*表示缓存区数据去可以被修改*/

    return b;
}

/*创建一个缓存区链表结构
1、从内存池缓存区链表中获取
2、如果内存去缓存区链表无可用，直接在内存池上申请
*/
ngx_chain_t *
ngx_alloc_chain_link(ngx_pool_t *pool)
{
    ngx_chain_t  *cl;

    cl = pool->chain;
    /* 
     * 首先从内存池中去取ngx_chain_t， 
     * 被清空的ngx_chain_t结构都会放在pool->chain 缓冲链上 
     */ 
    if (cl) {
        pool->chain = cl->next;
        return cl;
    }
    /* 如果取不到，则从内存池pool上分配一个数据结构  */
    cl = ngx_palloc(pool, sizeof(ngx_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}

/** 
 * 批量创建多个buf，并且用ngx_chain_t链表串起来，返回链表头 
 */ 
ngx_chain_t *
ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs)
{
    u_char       *p;
    ngx_int_t     i;
    ngx_buf_t    *b;
    ngx_chain_t  *chain, *cl, **ll;
    /* 在内存池pool上分配bufs->num个 buf缓冲区 ，每个大小为bufs->size */
    p = ngx_palloc(pool, bufs->num * bufs->size);
    if (p == NULL) {
        return NULL;
    }
    /*指向缓存区头节点*/
    ll = &chain;
    /* 循环创建ngx_buf_t，并且将ngx_buf_t挂载到ngx_chain_t链表上，并且返回链表*/ 
    for (i = 0; i < bufs->num; i++) {
        /* 最终调用的是内存池pool，主要申请ngx_buf_t结构体地址 */
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
        /*ngx_buf_t 结构体初始化缓存区域*/
        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        p += bufs->size;
        b->end = p;
       /*内存池上申请ngx_chain_t链表，用于挂接缓存区*/
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;
        *ll = cl;
        ll = &cl->next;
    }
    /*ngx_chain_t链表上最后一个置空*/
    *ll = NULL;

    return chain;
}

/*
*pool 内存池指针，主要用于申请ngx_chain_t结构体地址
*chain 目的ngx_chain_t 链表表头地址这个必须使用二级指针如果*chain =NULL,不会出错，
*in      源ngx_chain_t 链表表头地址，
*函数主要作用是讲源ngx_chain_t *in链表上的数据copy到目的ngx_chain_t 链表上
*/
ngx_int_t
ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;

    ll = chain;

    /*找到chain缓存区链表的最后一个节点，并讲最后一个节点
	的地址赋值 ll */
    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

   /* 遍历in 链表，讲in链表上的节点缓存区结构体copy到chain链表上*/ 
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
    /*目的ngx_chain_t 链表上的最后一个节点置空*/
    *ll = NULL;

    return NGX_OK;
}

/** 
 * 从空闲的ngx_chain_t链表上，获取一个未使用的ngx_chain_t节点
 *1、如果free 链表上有空闲节点，直接返回空闲节点指针；
 *2、如果无空闲节点，在内存池上申请ngx_chain_t及ngx_buf_t区节点，
 */ 
ngx_chain_t *
ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free)
{
    ngx_chain_t  *cl;
    /*1、如果free 链表上有空闲节点，直接返回空闲节点指针；*/
    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;
        return cl;
    }
    /*2、如果无空闲节点，在内存池上申请ngx_chain_t及ngx_buf_t区节点，*/
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
 * 释放BUF 
 * 1. 如果buf不为空，则不释放 
 * 2. 如果cl->buf->tag标记不一样，则直接还给Nginx的pool->chain链表 
 * 3. 如果buf为空，并且需要释放，则直接释放buf，并且放到free的空闲列表上 
 */
void
ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free, ngx_chain_t **busy,
    ngx_chain_t **out, ngx_buf_tag_t tag)
{
    ngx_chain_t  *cl;

   /*如果out不为空，将out挂接到busy链表上；
      并将out置空*/
    if (*out) {
       /*1 如果busy为空；out直接赋值给busy*/
        if (*busy == NULL) {
            *busy = *out;

        } else {
           /*busy 不为空，将out挂接到busy的链表的最后*/
            for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

            cl->next = *out;
        }

        *out = NULL;
    }
    /*遍历busy链表*/
    while (*busy) {
        cl = *busy;
        /*1 待处理数据不为0时，直接返回*/
        if (ngx_buf_size(cl->buf) != 0) {
            break;
        }
        /*2 模块标识不一致时，将当前节点从busy链表上拿走
		并挂接到内存池的链表上。*/
        if (cl->buf->tag != tag) {
            *busy = cl->next;
            ngx_free_chain(p, cl);
            continue;
        }
        /*3 将当前busy链表上的节点待处理数据置空*/
        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

	/*4 并将待当前节点挂接到free链表上去*/
        *busy = cl->next;
        cl->next = *free;
        *free = cl;
    }
}

/*处理文件类型，处理缓存区数据大小为limit*/
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

/*更新in链表缓存区数量,处理非文件类*/
ngx_chain_t *
ngx_chain_update_sent(ngx_chain_t *in, off_t sent)
{
    off_t  size;

    for ( /* void */ ; in; in = in->next) {
       /*如果节点是特殊缓存类型不处理*/
        if (ngx_buf_special(in->buf)) {
            continue;
        }

        if (sent == 0) {
            break;
        }
	 /*获取当前缓存区待处理数据的大小*/
        size = ngx_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;
	    /*待处理数据缓存区清空，即pos = last*/
            if (ngx_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;
            }
	     /*这个应该是dead core，前面有判断非文件类型*/
            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last;
            }

            continue;
        }

	/*如果是*/
        if (ngx_buf_in_memory(in->buf)) {
            in->buf->pos += (size_t) sent;
        }

        /*这个应该是dead core，前面有判断非文件类型*/
        if (in->buf->in_file) {
            in->buf->file_pos += sent;
        }

        break;
    }

    return in;
}
