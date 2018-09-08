
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;/* 清理的回调函数一般是ngx_pool_cleanup_file和ngx_pool_delete_file */
    void                 *data;  /* 指向存储的数据地址一般是ngx_pool_cleanup_file_t */
    ngx_pool_cleanup_t   *next;/* 下一个ngx_pool_cleanup_t */
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;

struct ngx_pool_large_s {
    ngx_pool_large_t     *next; /* 指向下一个存储地址 通过这个地址可以知道当前块长度 */ 
    void                 *alloc;   /* 数据块指针地址 */
};


typedef struct {
    u_char               *last;/* 内存池中未使用内存的开始节点地址 */
    u_char               *end; /* 内存池的结束地址 */
    ngx_pool_t           *next;/* 指向下一个内存池 */
    ngx_uint_t            failed;/* 失败次数,主要用于记录current后面内存池挂接的数量 考虑查找性能*/
} ngx_pool_data_t;


struct ngx_pool_s {
    ngx_pool_data_t       d;          /* 内存池的数据区域*/
    size_t                max;           /* 最大每次可分配内存 */
    ngx_pool_t           *current;  /* 指向当前的内存池指针地址。ngx_pool_t链表上最后一个缓存池结构*/
    ngx_chain_t          *chain;    /* 缓冲区链表 */
    ngx_pool_large_t     *large;  /* 存储大数据的链表 malloc申请内存需要注意内存释放*/
	
    ngx_pool_cleanup_t   *cleanup; /* 可自定义回调函数， 结构体及数据
    							data都是在内存池上申请，无需注意内存的释放*/
    ngx_log_t            *log;             /* 日志 */
};


typedef struct {
    ngx_fd_t              fd; /*文件描述符*/
    u_char               *name;/*文件的存储路径*/
    ngx_log_t            *log; /*log日志记录文件*/
} ngx_pool_cleanup_file_t;

/*主要完成内存池首个节点的初始化工作。*/
ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
/*主要完成内存池中挂接所有数据的释放，及内存池链表的数据释放*/
void ngx_destroy_pool(ngx_pool_t *pool);
/*应该是内存池数据不再使用时，内存池数据内部指针重新初始化*/
void ngx_reset_pool(ngx_pool_t *pool);

/*按照字节对其方式，在内存上申请size大小内容*/
void *ngx_palloc(ngx_pool_t *pool, size_t size);
/*按照非字节对其方式，在内存上申请size大小内容*/
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
/*按照字节对其方式，在内存上申请size大小内容并对申请内存进行初始化操作*/
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
/*申请大块内存地址，且挂在内存池*/
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
/*释放指定的大块内存地址*/
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
