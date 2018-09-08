
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
/*Nginxµƒbufª∫≥Â«¯ ˝æ›Ω·ππ£¨÷˜“™”√¿¥¥Ê¥¢∑«≥£¥ÛøÈµƒƒ⁄¥Ê°
£ngx_buf_t ˝æ›Ω·ππ“≤π·¥©¡À’˚∏ˆNginx°£Nginxµƒª∫≥Â«¯…Ëº∆ «±»Ωœ¡ÈªÓµƒ°£
1. ø…“‘◊‘∂®“Âπ‹¿Ì“µŒÒ≤„√Êµƒª∫≥Â«¯¡¥±Ì£ª
2. “≤ø…“‘Ω´ø’œ–µƒª∫≥Â«¯¡¥±ÌΩªªπ∏¯ƒ⁄¥Ê≥ÿpool->chainΩ·ππ°£
ª∫≥Â«¯ngx_buf_t «nginx¥¶¿Ì¥Û ˝æ›µƒπÿº¸ ˝æ›Ω·ππ£¨À¸º»”¶”√”⁄ƒ⁄¥Ê ˝æ›
“≤”¶”√”⁄¥≈≈Ã ˝æ›*/

ngx_buf_t *
ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t *b;

   /*‘⁄ƒ⁄¥Ê≥ÿ…œ…Í«Îngx_buf_tΩ·ππÃÂƒ⁄¥Ê£¨≤¢Ω¯––≥ı ºªØ*/
    b = ngx_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }
    /*‘⁄ƒ⁄¥Ê≥ÿ…œ…Í«Îsize¥Û–°µƒª∫¥Ê«¯£¨≤¢Ω¯––≥ı ºªØ*/
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
    
    b->pos = b->start; /*¥˝¥¶¿Ìª∫¥Ê∆˜µƒø™ º*/
    b->last = b->start;/*¥˝¥¶¿Ìª∫¥Ê∆˜µƒΩ·Œ≤*/
    b->end = b->last + size; /*ª∫¥Ê«¯Ω·Œ≤*/
    b->temporary = 1;   /*±Ì æª∫¥Ê«¯ ˝æ›»•ø…“‘±ª–ﬁ∏ƒ*/

    return b;
}

/*¥¥Ω®“ª∏ˆª∫¥Ê«¯¡¥±ÌΩ·ππ
1°¢¥”ƒ⁄¥Ê≥ÿª∫¥Ê«¯¡¥±Ì÷–ªÒ»°
2°¢»Áπ˚ƒ⁄¥Ê»•ª∫¥Ê«¯¡¥±ÌŒﬁø…”√£¨÷±Ω”‘⁄ƒ⁄¥Ê≥ÿ…œ…Í«Î
*/
ngx_chain_t *
ngx_alloc_chain_link(ngx_pool_t *pool)
{
    ngx_chain_t  *cl;

    cl = pool->chain;
    /* 
     *  ◊œ»¥”ƒ⁄¥Ê≥ÿ÷–»•»°ngx_chain_t£¨ 
     * ±ª«Âø’µƒngx_chain_tΩ·ππ∂ºª·∑≈‘⁄pool->chain ª∫≥Â¡¥…œ 
     */ 
    if (cl) {
        pool->chain = cl->next;
        return cl;
    }
    /* »Áπ˚»°≤ªµΩ£¨‘Ú¥”ƒ⁄¥Ê≥ÿpool…œ∑÷≈‰“ª∏ˆ ˝æ›Ω·ππ  */
    cl = ngx_palloc(pool, sizeof(ngx_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}

/** 
 * ≈˙¡ø¥¥Ω®∂‡∏ˆbuf£¨≤¢«“”√ngx_chain_t¡¥±Ì¥Æ∆¿¥£¨∑µªÿ¡¥±ÌÕ∑ 
 */ 
ngx_chain_t *
ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs)
{
    u_char       *p;
    ngx_int_t     i;
    ngx_buf_t    *b;
    ngx_chain_t  *chain, *cl, **ll;
    /* ‘⁄ƒ⁄¥Ê≥ÿpool…œ∑÷≈‰bufs->num∏ˆ bufª∫≥Â«¯ £¨√ø∏ˆ¥Û–°Œ™bufs->size */
    p = ngx_palloc(pool, bufs->num * bufs->size);
    if (p == NULL) {
        return NULL;
    }
    /*÷∏œÚª∫¥Ê«¯Õ∑Ω⁄µ„*/
    ll = &chain;
    /* —≠ª∑¥¥Ω®ngx_buf_t£¨≤¢«“Ω´ngx_buf_tπ“‘ÿµΩngx_chain_t¡¥±Ì…œ£¨≤¢«“∑µªÿ¡¥±Ì*/ 
    for (i = 0; i < bufs->num; i++) {
        /* ◊Ó÷’µ˜”√µƒ «ƒ⁄¥Ê≥ÿpool£¨÷˜“™…Í«Îngx_buf_tΩ·ππÃÂµÿ÷∑ */
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
        /*ngx_buf_t Ω·ππÃÂ≥ı ºªØª∫¥Ê«¯”Ú*/
        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        p += bufs->size;
        b->end = p;
       /*ƒ⁄¥Ê≥ÿ…œ…Í«Îngx_chain_t¡¥±Ì£¨”√”⁄π“Ω”ª∫¥Ê«¯*/
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;
        *ll = cl;
        ll = &cl->next;
    }
    /*ngx_chain_t¡¥±Ì…œ◊Ó∫Û“ª∏ˆ÷√ø’*/
    *ll = NULL;

    return chain;
}

/*
*pool ƒ⁄¥Ê≥ÿ÷∏’Î£¨÷˜“™”√”⁄…Í«Îngx_chain_tΩ·ππÃÂµÿ÷∑
*chain ƒøµƒngx_chain_t ¡¥±Ì±ÌÕ∑µÿ÷∑’‚∏ˆ±ÿ–Î π”√∂˛º∂÷∏’Î»Áπ˚*chain =NULL,≤ªª·≥ˆ¥Ì£¨
*in      ‘¥ngx_chain_t ¡¥±Ì±ÌÕ∑µÿ÷∑£¨
*∫Ø ˝÷˜“™◊˜”√ «Ω≤‘¥ngx_chain_t *in¡¥±Ì…œµƒ ˝æ›copyµΩƒøµƒngx_chain_t ¡¥±Ì…œ
*/
ngx_int_t
ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;

    ll = chain;

    /*’“µΩchainª∫¥Ê«¯¡¥±Ìµƒ◊Ó∫Û“ª∏ˆΩ⁄µ„£¨≤¢Ω≤◊Ó∫Û“ª∏ˆΩ⁄µ„
	µƒµÿ÷∑∏≥÷µ ll */
    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

   /* ±È¿˙in ¡¥±Ì£¨Ω≤in¡¥±Ì…œµƒΩ⁄µ„ª∫¥Ê«¯Ω·ππÃÂcopyµΩchain¡¥±Ì…œ*/ 
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
    /*ƒøµƒngx_chain_t ¡¥±Ì…œµƒ◊Ó∫Û“ª∏ˆΩ⁄µ„÷√ø’*/
    *ll = NULL;

    return NGX_OK;
}

/** 
 * ¥”ø’œ–µƒngx_chain_t¡¥±Ì…œ£¨ªÒ»°“ª∏ˆŒ¥ π”√µƒngx_chain_tΩ⁄µ„
 *1°¢»Áπ˚free ¡¥±Ì…œ”–ø’œ–Ω⁄µ„£¨÷±Ω”∑µªÿø’œ–Ω⁄µ„÷∏’Î£ª
 *2°¢»Áπ˚Œﬁø’œ–Ω⁄µ„£¨‘⁄ƒ⁄¥Ê≥ÿ…œ…Í«Îngx_chain_tº∞ngx_buf_t«¯Ω⁄µ„£¨
 */ 
ngx_chain_t *
ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free)
{
    ngx_chain_t  *cl;
    /*1°¢»Áπ˚free ¡¥±Ì…œ”–ø’œ–Ω⁄µ„£¨÷±Ω”∑µªÿø’œ–Ω⁄µ„÷∏’Î£ª*/
    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;
        return cl;
    }
    /*2°¢»Áπ˚Œﬁø’œ–Ω⁄µ„£¨‘⁄ƒ⁄¥Ê≥ÿ…œ…Í«Îngx_chain_tº∞ngx_buf_t«¯Ω⁄µ„£¨*/
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
 *  Õ∑≈BUF 
 * 1. »Áπ˚buf≤ªŒ™ø’£¨‘Ú≤ª Õ∑≈ 
 * 2. »Áπ˚cl->buf->tag±Íº«≤ª“ª—˘£¨‘Ú÷±Ω”ªπ∏¯Nginxµƒpool->chain¡¥±Ì 
 * 3. »Áπ˚bufŒ™ø’£¨≤¢«“–Ë“™ Õ∑≈£¨‘Ú÷±Ω” Õ∑≈buf£¨≤¢«“∑≈µΩfreeµƒø’œ–¡–±Ì…œ 
 */
void
ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free, ngx_chain_t **busy,
    ngx_chain_t **out, ngx_buf_tag_t tag)
{
    ngx_chain_t  *cl;

   /*»Áπ˚out≤ªŒ™ø’£¨Ω´outπ“Ω”µΩbusy¡¥±Ì…œ£ª
      ≤¢Ω´out÷√ø’*/
    if (*out) {
       /*1 »Áπ˚busyŒ™ø’£ªout÷±Ω”∏≥÷µ∏¯busy*/
        if (*busy == NULL) {
            *busy = *out;

        } else {
           /*busy ≤ªŒ™ø’£¨Ω´outπ“Ω”µΩbusyµƒ¡¥±Ìµƒ◊Ó∫Û*/
            for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

            cl->next = *out;
        }

        *out = NULL;
    }
    /*±È¿˙busy¡¥±Ì*/
    while (*busy) {
        cl = *busy;
        /*1 ¥˝¥¶¿Ì ˝æ›≤ªŒ™0 ±£¨÷±Ω”∑µªÿ*/
        if (ngx_buf_size(cl->buf) != 0) {
            break;
        }
        /*2 ƒ£øÈ±Í ∂≤ª“ª÷¬ ±£¨Ω´µ±«∞Ω⁄µ„¥”busy¡¥±Ì…œƒ√◊ﬂ
		≤¢π“Ω”µΩƒ⁄¥Ê≥ÿµƒ¡¥±Ì…œ°£*/
        if (cl->buf->tag != tag) {
            *busy = cl->next;
            ngx_free_chain(p, cl);
            continue;
        }
        /*3 Ω´µ±«∞busy¡¥±Ì…œµƒΩ⁄µ„¥˝¥¶¿Ì ˝æ›÷√ø’*/
        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

	/*4 ≤¢Ω´¥˝µ±«∞Ω⁄µ„π“Ω”µΩfree¡¥±Ì…œ»•*/
        *busy = cl->next;
        cl->next = *free;
        *free = cl;
    }
}

/*¥¶¿ÌŒƒº˛¿‡–Õ£¨¥¶¿Ìª∫¥Ê«¯ ˝æ›¥Û–°Œ™limit*/
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

/*∏¸–¬in¡¥±Ìª∫¥Ê«¯ ˝¡ø,¥¶¿Ì∑«Œƒº˛¿‡*/
ngx_chain_t *
ngx_chain_update_sent(ngx_chain_t *in, off_t sent)
{
    off_t  size;

    for ( /* void */ ; in; in = in->next) {
       /*»Áπ˚Ω⁄µ„ «Ãÿ ‚ª∫¥Ê¿‡–Õ≤ª¥¶¿Ì*/
        if (ngx_buf_special(in->buf)) {
            continue;
        }

        if (sent == 0) {
            break;
        }
	 /*ªÒ»°µ±«∞ª∫¥Ê«¯¥˝¥¶¿Ì ˝æ›µƒ¥Û–°*/
        size = ngx_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;
	    /*¥˝¥¶¿Ì ˝æ›ª∫¥Ê«¯«Âø’£¨º¥pos = last*/
            if (ngx_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;
            }
	     /*’‚∏ˆ”¶∏√ «dead core£¨«∞√Ê”–≈–∂œ∑«Œƒº˛¿‡–Õ*/
            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last;
            }

            continue;
        }

	/*»Áπ˚ «*/
        if (ngx_buf_in_memory(in->buf)) {
            in->buf->pos += (size_t) sent;
        }

        /*’‚∏ˆ”¶∏√ «dead core£¨«∞√Ê”–≈–∂œ∑«Œƒº˛¿‡–Õ*/
        if (in->buf->in_file) {
            in->buf->file_pos += sent;
        }

        break;
    }

    return in;
}
