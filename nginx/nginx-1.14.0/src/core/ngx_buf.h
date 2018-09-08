
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

struct ngx_buf_s {
	/*
     * pos通常是用来告诉使用者本次应该从pos这个位置开始处理内存中的数据，这样设置是因为同一个
     * ngx_buf_t可能被多次反复处理。当然，pos的含义是由使用它的模板定义的
     */
    u_char          *pos;
    /* last通常表示有效的内容到此为止，注意，pos与last之间的内存是希望nginx处理的内容 */
    u_char          *last;
    off_t            file_pos;      /* 处理文件时，待处理的文件开始标记  */
    off_t            file_last;      /* 处理文件时，待处理的文件结尾标记  */

    u_char          *start;         /* 缓冲区开始的指针地址 */
    u_char          *end;          /* 缓冲区结尾的指针地址 */
    ngx_buf_tag_t    tag;        /*  表示当前缓冲区的类型，例如由哪个模块使用就指向这个模块ngx_module_t变量的地址，是一个void类型的指针。 */
    ngx_file_t      *file;           /* 引用的文件 */   
    /*
     * 当前缓冲区的影子缓冲区，该成员很少用到。当缓冲区转发上游服务器的响应时才使用了shadow成员，
     * 这是因为nginx太节约内存了，分配一块内存并使用ngx_buf_t表示接收到的上游服务器响应后，
     * 在向下游客户端转发时可能会把这块内存存储到文件中，也可能直接向下游发送，此时nginx绝对不会
     * 重新复制一份内存用于新的目的，而是再次建立一个ngx_buf_t结构体指向原内存，这样多个ngx_buf_t
     * 结构体指向了同一份内存，它们之间的关系就通过shadow成员来引用，一般不建议使用。
     */
    ngx_buf_t       *shadow;   


    /* the buf's content could be changed */
    unsigned         temporary:1;  /* 标志位，为1时，内存可修改 */ 

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned         memory:1;   /* 标志位，为1时，内存只读 */

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;     /* 标志位，为1时，mmap映射过来的内存，不可修改 */

    unsigned         recycled:1;  /* 标志位，为1时，可回收 */
    unsigned         in_file:1;     /* 标志位，为1时，表示处理的是文件 */
    unsigned         flush:1;       /* 标志位，为1时，表示需要进行flush操作 */
	 /*
     * 标志位，对于操作这块缓冲区时是否使用同步方式，需谨慎考虑，这可能会阻塞nginx进程，nginx中所有
     * 操作几乎都是异步的，这是它支持高并发的关键。有些框架代码在sync为1时可能会有阻塞的方式进行I/O
     * 操作，它的意义视使用它的nginx模块而定。
     */
    unsigned         sync:1; 
    unsigned         last_buf:1;   /* 标志位，为1时，表示为缓冲区链表ngx_chain_t上的最后一块待处理缓冲区 */
    unsigned         last_in_chain:1; /* 标志位，为1时，表示为缓冲区链表ngx_chain_t上的最后一块缓冲区 */

    unsigned         last_shadow:1; /* 标志位，为1时，表示是否是最后一个影子缓冲区 */
    unsigned         temp_file:1;    /* 标志位，为1时，表示当前缓冲区是否属于临时文件 */

    /* STUB */ int   num;
};

/*缓存区链表结构，用于挂在内存池上使用
1. Nginx的缓冲区数据结构主要包含链表数据结构ngx_chain_t和buf数据结构ngx_buf_t

2. Nginx可以在自定义的业务层面管理繁忙busy和空闲free的缓冲区链表结构。通过后边的函数，可以对缓冲区的链表结构和buf结构进行管理。

3. 如果缓冲区链表需要被回收，则会放到Nginx内存池的pool->chain链表上。

4. 缓冲区是Nginx用的非常多的一种数据结构，主要用于接收和输出HTTP的数据信息。所以对Nginx的缓冲区的数据结构深入理解非常有必要。

*/
struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};

/*用于批量申请缓存区*/
typedef struct {
    ngx_int_t    num;/*缓存区的数量*/
    size_t       size;/*缓存区的大小*/
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);

struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
    unsigned                     unaligned:1;
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
    unsigned                     aio:1;

#if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
    ngx_output_chain_aio_pt      aio_handler;
#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    ssize_t                    (*aio_preload)(ngx_buf_t *file);
#endif
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
                                                 ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;

    ngx_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !ngx_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
#define ngx_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
