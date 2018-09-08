
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
    ngx_pool_cleanup_pt   handler;/* �����Ļص�����һ����ngx_pool_cleanup_file��ngx_pool_delete_file */
    void                 *data;  /* ָ��洢�����ݵ�ַһ����ngx_pool_cleanup_file_t */
    ngx_pool_cleanup_t   *next;/* ��һ��ngx_pool_cleanup_t */
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;

struct ngx_pool_large_s {
    ngx_pool_large_t     *next; /* ָ����һ���洢��ַ ͨ�������ַ����֪����ǰ�鳤�� */ 
    void                 *alloc;   /* ���ݿ�ָ���ַ */
};


typedef struct {
    u_char               *last;/* �ڴ����δʹ���ڴ�Ŀ�ʼ�ڵ��ַ */
    u_char               *end; /* �ڴ�صĽ�����ַ */
    ngx_pool_t           *next;/* ָ����һ���ڴ�� */
    ngx_uint_t            failed;/* ʧ�ܴ���,��Ҫ���ڼ�¼current�����ڴ�عҽӵ����� ���ǲ�������*/
} ngx_pool_data_t;


struct ngx_pool_s {
    ngx_pool_data_t       d;          /* �ڴ�ص���������*/
    size_t                max;           /* ���ÿ�οɷ����ڴ� */
    ngx_pool_t           *current;  /* ָ��ǰ���ڴ��ָ���ַ��ngx_pool_t���������һ������ؽṹ*/
    ngx_chain_t          *chain;    /* ���������� */
    ngx_pool_large_t     *large;  /* �洢�����ݵ����� malloc�����ڴ���Ҫע���ڴ��ͷ�*/
	
    ngx_pool_cleanup_t   *cleanup; /* ���Զ���ص������� �ṹ�弰����
    							data�������ڴ�������룬����ע���ڴ���ͷ�*/
    ngx_log_t            *log;             /* ��־ */
};


typedef struct {
    ngx_fd_t              fd; /*�ļ�������*/
    u_char               *name;/*�ļ��Ĵ洢·��*/
    ngx_log_t            *log; /*log��־��¼�ļ�*/
} ngx_pool_cleanup_file_t;

/*��Ҫ����ڴ���׸��ڵ�ĳ�ʼ��������*/
ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
/*��Ҫ����ڴ���йҽ��������ݵ��ͷţ����ڴ�������������ͷ�*/
void ngx_destroy_pool(ngx_pool_t *pool);
/*Ӧ�����ڴ�����ݲ���ʹ��ʱ���ڴ�������ڲ�ָ�����³�ʼ��*/
void ngx_reset_pool(ngx_pool_t *pool);

/*�����ֽڶ��䷽ʽ�����ڴ�������size��С����*/
void *ngx_palloc(ngx_pool_t *pool, size_t size);
/*���շ��ֽڶ��䷽ʽ�����ڴ�������size��С����*/
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
/*�����ֽڶ��䷽ʽ�����ڴ�������size��С���ݲ��������ڴ���г�ʼ������*/
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
/*�������ڴ��ַ���ҹ����ڴ��*/
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
/*�ͷ�ָ���Ĵ���ڴ��ַ*/
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */