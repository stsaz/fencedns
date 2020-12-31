/** fencedns: DNS response cache
2020, Simon Zolin */

#include <dns/dnsmod.h>
#include <ffbase/vector.h>
#include <ffbase/string.h>
#include <ffbase/map.h>
#include <ffbase/rbtree.h>
#include <FFOS/std.h>

#define debug(...)  cx->core->log(LOG_DEBUG, __VA_ARGS__)

struct cache_conf {
	ffuint min_ttl;
	ffuint error_ttl;
	ffuint nxdomain_ttl;
	ffuint max_size;
};

static const ffconf_arg cache_args[] = {
	{ "min_ttl",	FFCONF_TINT32, FF_OFF(struct cache_conf, min_ttl) },
	{ "error_ttl",	FFCONF_TINT32, FF_OFF(struct cache_conf, error_ttl) },
	{ "nxdomain_ttl",	FFCONF_TINT32, FF_OFF(struct cache_conf, nxdomain_ttl) },
	{ "max_size",	FFCONF_TINT32, FF_OFF(struct cache_conf, max_size) },
	{},
};

struct cache_ctx {
	struct cache_conf conf;
	fdns_core *core;
	ffmap cache; // { qtype, qname } -> entry*
	ffrbtree timetree;
	ffsize total_size;
	ffuint misses, hits;
};

static struct cache_ctx *cx;

struct entry {
	ffrbt_node expire_node;
	ffstr key; // type[4], name[]
	ffstr name;
	ffstr data;
	char sdata[0];
};

static ffsize entry_size(struct entry *ce)
{
	return sizeof(struct entry) + ce->key.len + ce->data.len;
}

static void entry_free(struct entry *ce)
{
	ffmem_free(ce);
}

static void entry_remove(struct cache_ctx *cx, struct entry *ce, ffuint hash)
{
	ffrbt_rm(&cx->timetree, &ce->expire_node);
	ffmap_rm_hash(&cx->cache, hash, ce);
	cx->total_size -= entry_size(ce);
	entry_free(ce);
}

static int map_keyeq(void *opaque, const void *key, ffsize keylen, void *val)
{
	(void)opaque;
	const struct entry *ce = val;
	return ffstr_eq(&ce->key, key, keylen);
}

static void cache_clear(struct cache_ctx *cx)
{
	struct _ffmap_item *it;
	FFMAP_WALK(&cx->cache, it) {
		if (!_ffmap_item_occupied(it))
			continue;
		struct entry *ce = it->val;
		entry_free(ce);
	}
	ffmap_free(&cx->cache);
	ffmap_init(&cx->cache, map_keyeq);
	ffrbt_init(&cx->timetree);
}

static void cache_destroy(struct cache_ctx *c)
{
	cache_clear(c);
	ffmem_free(c);
}

static struct entry* entry_new(const ffdns_question *q, ffstr data, ffuint *new_size)
{
	*new_size = sizeof(struct entry) + 4 + q->name.len + data.len;
	struct entry *ce = ffmem_alloc(*new_size);
	ffuint dataoff = 4 + q->name.len;
	ffstr_set(&ce->name, &ce->sdata[4], q->name.len);
	ffstr_set(&ce->key, ce->sdata, dataoff);
	ffstr_set(&ce->data, &ce->sdata[dataoff], data.len);

	*(ffuint*)ce->sdata = q->type;
	ffs_lower(ce->name.ptr, ce->name.len, q->name.ptr, q->name.len);
	ffmem_copy(ce->data.ptr, data.ptr, data.len);
	return ce;
}

/** Remove old entries until there's enough free space */
static void remove_old(struct cache_ctx *cx, ffuint new_size)
{
	struct entry *ce;
	while (cx->total_size + new_size >= cx->conf.max_size) {
		ffrbt_node *node = ffrbt_first(&cx->timetree);
		FF_ASSERT(node != &cx->timetree.sentl);
		ce = FF_STRUCTPTR(struct entry, expire_node, node);
		debug("cache: removing entry %S", &ce->name);
		ffuint hash2 = ffmap_hash(ce->key.ptr, ce->key.len);
		entry_remove(cx, ce, hash2);
	}
}

/** Get TTL according to configuration */
static ffuint get_ttl(const struct dns_msg *msg)
{
	ffuint ttl;
	switch (msg->h.rcode) {
	case FFDNS_NOERROR:
		// ttl=-1 means that there are no answer records in this message
		ttl = (msg->ttl != (uint)-1) ? msg->ttl : 0;
		ttl = ffmax(ttl, cx->conf.min_ttl);
		break;
	case FFDNS_NXDOMAIN:
		ttl = cx->conf.nxdomain_ttl;
		break;
	default:
		ttl = cx->conf.error_ttl;
	}
	return ttl;
}

/*
. don't cache response with error code if configured so
. allocate a new element
. remove the existing entry from cache, if any
. check if new element fits in cache
  . remove old elements
. add new element
*/
static void cache_add(struct cache_ctx *cx, const struct dns_msg *msg, ffstr data)
{
	if (msg->h.rcode != FFDNS_NOERROR && cx->conf.error_ttl == 0)
		return;

	ffuint ttl = get_ttl(msg);
	if (ttl == 0)
		return;

	ffuint new_size;
	struct entry *ce, *ce2;
	ce = entry_new(&msg->q, data, &new_size);
	ffuint hash = ffmap_hash(ce->key.ptr, ce->key.len);
	ce2 = ffmap_find_hash(&cx->cache, hash, ce->key.ptr, ce->key.len, NULL);
	if (ce2 != NULL) {
		debug("cache: overwriting entry %S", &ce2->name);
		entry_remove(cx, ce2, hash);
		ce2 = NULL;
	}

	if (new_size >= cx->conf.max_size) {
		debug("cache: too large entry");
		goto end;
	}

	remove_old(cx, new_size);

	fftime expire = cx->core->time(FDNS_TIME_MONO, NULL);
	expire.sec += ttl;

	if (0 != ffmap_add_hash(&cx->cache, hash, ce))
		goto end;

	ce->expire_node.key = expire.sec;
	ffrbt_insert(&cx->timetree, &ce->expire_node, NULL);
	cx->total_size += entry_size(ce);
	debug("cache: stored %u %S %uB ttl=%u [%L/%L]"
		, msg->q.type, &ce->name, new_size, ttl
		, cx->total_size, cx->cache.len);
	ce = NULL;

end:
	if (ce != NULL)
		entry_free(ce);
}

static ffvec cache_key(const ffdns_question *q)
{
	ffvec key = {};
	ffvec_addT(&key, &q->type, 4, char);
	ffvec_addT(&key, q->name.ptr, q->name.len, char);
	return key;
}

/*
. search element in cache
. check if expired - remove if so
. return the found element
*/
static int cache_find(struct cache_ctx *cx, const ffdns_question *q, ffstr *data)
{
	ffvec key = cache_key(q);
	ffuint hash = ffmap_hash(key.ptr, key.len);
	struct entry *ce = ffmap_find_hash(&cx->cache, hash, key.ptr, key.len, NULL);
	ffvec_free(&key);

	if (ce == NULL) {
		cx->misses++;
		return -1;
	}

	fftime now = cx->core->time(FDNS_TIME_MONO, NULL);
	int ttl = ce->expire_node.key - now.sec;
	if (ttl <= 0) {
		debug("cache: entry %S has expired", &ce->name);
		entry_remove(cx, ce, hash);
		cx->misses++;
		return -1;
	}

	cx->hits++;
	*data = ce->data;
	debug("cache: found %u %S ttl:%u [%u:%u]"
		, q->type, &ce->name, ttl
		, cx->misses, cx->hits);
	return ttl;
}

/** Set TTL value on all answer records */
static void set_ttl(struct cache_ctx *cx, ffstr resp, ffuint ttl)
{
	ffdns_header h = {};
	ffuint i = ffdns_header_read(&h, resp);
	i += ffdns_question_read(NULL, resp);
	for (ffuint ia = 0;  ia != h.answers;  ia++) {
		int aoff = ffdns_name_read(NULL, resp, i);
		struct ffdns_ans *a = (struct ffdns_ans*)&resp.ptr[i + aoff];
		*(ffuint*)a->ttl = ffint_be_cpu32(ttl);
		i += ffdns_answer_read(NULL, resp, i);
	}
}

int cache_process_req(struct client *c)
{
	if (cx->conf.max_size == 0)
		return DNS_CONTINUE;

	ffstr resp;
	int ttl = cache_find(cx, &c->req.q, &resp);
	if (ttl < 0)
		return DNS_CONTINUE;

	ffvec_add2T(&c->respbuf, &resp, char);
	struct ffdns_hdr *hh = (struct ffdns_hdr*)c->respbuf.ptr;
	*(ffushort*)hh->id = ffint_be_cpu16(c->req.h.id);
	ffstr_set2(&resp, &c->respbuf);
	set_ttl(cx, resp, ttl);
	c->status = "cache";
	return DNS_FIN;
}

int cache_process_resp(struct client *c)
{
	if (cx->conf.max_size == 0)
		return DNS_CONTINUE;

	cache_add(cx, &c->resp, c->resp.data);
	return DNS_CONTINUE;
}

static void cache_conf(fdns_core *core, const ffconf_arg **conf_args, void **conf_obj)
{
	cx = ffmem_new(struct cache_ctx);
	cx->core = core;
	cx->conf.min_ttl = 3600;
	cx->conf.error_ttl = 5;
	cx->conf.nxdomain_ttl = cx->conf.error_ttl;
	cx->conf.max_size = 4*1024*1024;
	ffmap_init(&cx->cache, map_keyeq);
	ffrbt_init(&cx->timetree);

	*conf_args = cache_args;
	*conf_obj = cx;
}

static int cache_sig(int sig)
{
	switch (sig) {
	case FDNS_SIG_CLEAR:
		cache_clear(cx);
		break;

	case FDNS_SIG_DESTROY:
		cache_destroy(cx);
		cx = NULL;
		break;
	}
	return 0;
}

struct fdns_mod cache_mod = {
	"cache",
	cache_conf, cache_sig,
};
