
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
     * posͨ������������ʹ���߱���Ӧ�ô�pos���λ�ÿ�ʼ�����ڴ��е����ݣ�������������Ϊͬһ��
     * ngx_buf_t���ܱ���η���������Ȼ��pos�ĺ�������ʹ������ģ�嶨���
     */
    u_char          *pos;
    /* lastͨ����ʾ��Ч�����ݵ���Ϊֹ��ע�⣬pos��last֮����ڴ���ϣ��nginx��������� */
    u_char          *last;
    off_t            file_pos;      /* �����ļ�ʱ����������ļ���ʼ���  */
    off_t            file_last;      /* �����ļ�ʱ����������ļ���β���  */

    u_char          *start;         /* ��������ʼ��ָ���ַ */
    u_char          *end;          /* ��������β��ָ���ַ */
    ngx_buf_tag_t    tag;        /*  ��ʾ��ǰ�����������ͣ��������ĸ�ģ��ʹ�þ�ָ�����ģ��ngx_module_t�����ĵ�ַ����һ��void���͵�ָ�롣 */
    ngx_file_t      *file;           /* ���õ��ļ� */   
    /*
     * ��ǰ��������Ӱ�ӻ��������ó�Ա�����õ�����������ת�����η���������Ӧʱ��ʹ����shadow��Ա��
     * ������Ϊnginx̫��Լ�ڴ��ˣ�����һ���ڴ沢ʹ��ngx_buf_t��ʾ���յ������η�������Ӧ��
     * �������οͻ���ת��ʱ���ܻ������ڴ�洢���ļ��У�Ҳ����ֱ�������η��ͣ���ʱnginx���Բ���
     * ���¸���һ���ڴ������µ�Ŀ�ģ������ٴν���һ��ngx_buf_t�ṹ��ָ��ԭ�ڴ棬�������ngx_buf_t
     * �ṹ��ָ����ͬһ���ڴ棬����֮��Ĺ�ϵ��ͨ��shadow��Ա�����ã�һ�㲻����ʹ�á�
     */
    ngx_buf_t       *shadow;   


    /* the buf's content could be changed */
    unsigned         temporary:1;  /* ��־λ��Ϊ1ʱ���ڴ���޸� */ 

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned         memory:1;   /* ��־λ��Ϊ1ʱ���ڴ�ֻ�� */

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;     /* ��־λ��Ϊ1ʱ��mmapӳ��������ڴ棬�����޸� */

    unsigned         recycled:1;  /* ��־λ��Ϊ1ʱ���ɻ��� */
    unsigned         in_file:1;     /* ��־λ��Ϊ1ʱ����ʾ��������ļ� */
    unsigned         flush:1;       /* ��־λ��Ϊ1ʱ����ʾ��Ҫ����flush���� */
	 /*
     * ��־λ�����ڲ�����黺����ʱ�Ƿ�ʹ��ͬ����ʽ����������ǣ�����ܻ�����nginx���̣�nginx������
     * �������������첽�ģ�������֧�ָ߲����Ĺؼ�����Щ��ܴ�����syncΪ1ʱ���ܻ��������ķ�ʽ����I/O
     * ����������������ʹ������nginxģ�������
     */
    unsigned         sync:1; 
    unsigned         last_buf:1;   /* ��־λ��Ϊ1ʱ����ʾΪ����������ngx_chain_t�ϵ����һ����������� */
    unsigned         last_in_chain:1; /* ��־λ��Ϊ1ʱ����ʾΪ����������ngx_chain_t�ϵ����һ�黺���� */

    unsigned         last_shadow:1; /* ��־λ��Ϊ1ʱ����ʾ�Ƿ������һ��Ӱ�ӻ����� */
    unsigned         temp_file:1;    /* ��־λ��Ϊ1ʱ����ʾ��ǰ�������Ƿ�������ʱ�ļ� */

    /* STUB */ int   num;
};

/*����������ṹ�����ڹ����ڴ����ʹ��
1. Nginx�Ļ��������ݽṹ��Ҫ�����������ݽṹngx_chain_t��buf���ݽṹngx_buf_t

2. Nginx�������Զ����ҵ��������æbusy�Ϳ���free�Ļ���������ṹ��ͨ����ߵĺ��������ԶԻ�����������ṹ��buf�ṹ���й���

3. ���������������Ҫ�����գ����ŵ�Nginx�ڴ�ص�pool->chain�����ϡ�

4. ��������Nginx�õķǳ����һ�����ݽṹ����Ҫ���ڽ��պ����HTTP��������Ϣ�����Զ�Nginx�Ļ����������ݽṹ�������ǳ��б�Ҫ��

*/
struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};

/*�����������뻺����*/
typedef struct {
    ngx_int_t    num;/*������������*/
    size_t       size;/*�������Ĵ�С*/
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
