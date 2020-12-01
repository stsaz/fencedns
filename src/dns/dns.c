/** fencedns: DNS server
2020, Simon Zolin */

#include <fencedns.h>
#include <dns/dnsmod.h>
#include <dns/client.h>
#include <FF/net/url.h>
#include <FFOS/perf.h>
#include <FFOS/signal.h>

static struct dnsmod *g;


int conf_bind(ffconf_scheme *cs, void *obj, ffstr *val)
{
	if (0 != ffsockaddr_fromstr(&g->conf.bind, val->ptr, val->len, 53))
		return FFCONF_EBADVAL;
	return 0;
}

int conf_block_mode(ffconf_scheme *cs, void *obj, ffstr *val)
{
	// enum BLOCK_MODE
	static const char *const blockmode_str[] = {
		"nxdomain",
		"refused",
		"empty",
		"null_ip",
		"local_ip",
		"drop",
	};
	int i = ffszarr_find(blockmode_str, FF_COUNT(blockmode_str), val->ptr, val->len);
	if (i < 0)
		return FFCONF_EBADVAL;
	g->conf.block_mode = i;
	return 0;
}

int conf_cache(ffconf_scheme *cs, void *obj)
{
	const ffconf_arg *conf_args;
	void *conf_obj;
	cache_mod.conf(&dns_core, &conf_args, &conf_obj);
	ffconf_scheme_addctx(cs, conf_args, conf_obj);
	return 0;
}

int conf_hosts(ffconf_scheme *cs, void *obj)
{
	const ffconf_arg *conf_args;
	void *conf_obj;
	hosts_mod.conf(&dns_core, &conf_args, &conf_obj);
	ffconf_scheme_addctx(cs, conf_args, conf_obj);
	return 0;
}

int conf_upstream(ffconf_scheme *cs, void *obj)
{
	const ffconf_arg *conf_args;
	void *conf_obj;
	upstream_mod.conf(&dns_core, &conf_args, &conf_obj);
	ffconf_scheme_addctx(cs, conf_args, conf_obj);
	return 0;
}

const ffconf_arg dns_args[] = {
	{ "bind",	FFCONF_TSTR, (ffsize)conf_bind },
	{ "block_ttl",	FFCONF_TINT32, FF_OFF(struct dns_conf, block_ttl) },
	{ "block_aaaa",	FFCONF_TBOOL, FF_OFF(struct dns_conf, block_aaaa) },
	{ "block_mode",	FFCONF_TSTR, (ffsize)conf_block_mode },
	{ "cache",	FFCONF_TOBJ, (ffsize)conf_cache },
	{ "hosts",	FFCONF_TOBJ, (ffsize)conf_hosts },
	{ "upstream",	FFCONF_TOBJ, (ffsize)conf_upstream },
	{},
};


int client_map_keyeq(void *opaque, const void *key, ffsize keylen, void *val)
{
	(void)opaque;
	FF_ASSERT(keylen == 2);
	ffushort id = *(ffushort*)key;
	const struct client *c = val;
	return (id == c->req.h.id);
}

int lisn_init(struct dnsmod *s)
{
	s->sk = ffsock_create_udp(AF_INET, FFSOCK_NONBLOCK);
	if (s->sk == FFSOCK_NULL) {
		fatal("ffsock_create_udp: %E", fferr_last());
		return -1;
	}
	int r = ffsock_bind(s->sk, &s->conf.bind);
	if (r < 0) {
		fatal("ffsock_bind: %E", fferr_last());
		return -1;
	}

	if (0 != ffkq_attach_socket(s->kq, s->sk, NULL, FFKQ_READ)) {
		fatal("ffkq_attach_socket: %E", fferr_last());
		return -1;
	}

	ffuint port = 0;
	ffsockaddr_ip_port(&s->conf.bind, &port);
	debug("listening on %d", port);
	return 0;
}

int srv_prepare(struct dnsmod *s)
{
	ffmap_init(&s->clients, client_map_keyeq);
	ffvec_reallocT(&s->inbuf, 4*1024, char);

	if (FFTIMER_NULL == (s->timer_fd = fftimer_create(0))) {
		fatal("fftimer_create: %E", fferr_last());
		return -1;
	}
	fftimerqueue_init(&s->timerq);

	s->kq = ffkq_create();
	if (s->kq == FFKQ_NULL) {
		fatal("ffkq_create: %E", fferr_last());
		return -1;
	}
	s->postev = ffkq_post_attach(s->kq, (void*)2);
	if (s->postev == FFKQ_NULL) {
		fatal("ffkq_post_attach: %E", fferr_last());
		return -1;
	}

	dns_core.kq = s->kq;

	if (0 != fftimer_start(s->timer_fd, g->kq, (void*)3, 500)) {
		fatal("fftimer_start: %E", fferr_last());
		return -1;
	}

	if (0 != lisn_init(s))
		return -1;

	return 0;
}

void srv_close(struct dnsmod *s)
{
	ffkq_post_detach(s->postev, s->kq);  s->postev = FFKQ_NULL;
	ffkq_close(s->kq);  s->kq = FFKQ_NULL;
	ffsock_close(s->sk);  s->sk = FFSOCK_NULL;
	ffvec_free(&s->inbuf);

	struct _ffmap_item *it;
	FFMAP_WALK(&s->clients, it) {
		if (!_ffmap_item_occupied(it))
			continue;
		struct client *c = it->val;
		client_free(c);
	}
	ffmap_free(&s->clients);
}

void cli_start(struct dnsmod *s, ffstr data, ffsockaddr *peer)
{
	struct client *c = ffmem_new(struct client);
	c->srv = s;

	ffuint uid = ++s->client_uid;
	c->uid.ptr = c->uid_s;
	c->uid.len = ffs_format(c->uid_s, sizeof(c->uid_s), "*%u", uid);

	c->peer = *peer;
	c->reqbuf = data;
	cli_conveyer(c);
}

void srv_addclient(struct dnsmod *s, ffuint id, struct client *c)
{
	ffushort qid = id;
	ffmap_add(&s->clients, &qid, 2, c);
	c->in_list = 1;
	debug("srv: added client %u 0x%p [%L]", id, c, s->clients.len);
}

void srv_rmclient(struct dnsmod *s, ffuint id, struct client *c)
{
	if (!c->in_list)
		return;
	ffushort qid = id;
	ffuint hash = ffmap_hash(&qid, 2);
	if (0 == ffmap_rm_hash(&s->clients, hash, c))
		debug("srv: removed client %u 0x%p [%L]", id, c, s->clients.len);
}

struct client* srv_findclient(struct dnsmod *s, ffuint id)
{
	ffushort qid = id;
	struct client *c = ffmap_find(&s->clients, &qid, 2, NULL);
	if (c == NULL)
		warning("upstream: no client with ID %u", id);
	return c;
}

int srv_read_process1(struct dnsmod *s)
{
	ffsockaddr peer;
	int r = ffsock_recvfrom(s->sk, s->inbuf.ptr, 4*1024, 0, &peer);
	if (r < 0) {
		if (!fferr_again(fferr_last()))
			error("ffsock_recvfrom: %E", fferr_last());
		return -1;
	}
	s->in_reqs++;

	ffstr data;
	ffstr_set(&data, s->inbuf.ptr, r);
	ffvec_null(&s->inbuf);
	cli_start(s, data, &peer);

	ffvec_reallocT(&s->inbuf, 4*1024, char);
	return 0;
}

void srv_read_process(struct dnsmod *s)
{
	for (;;) {
		int r = srv_read_process1(s);
		if (r < 0)
			break;
	}
}

void tmr_process(struct dnsmod *s)
{
	fftimer_consume(s->timer_fd);
	fftime now = fftime_monotonic();
	ffuint msec = fftime_to_msec(&now);
	fftimerqueue_process(&s->timerq, msec);
}

int srv_work(struct dnsmod *s)
{
	ffkq_event ev[8];
	ffkq_time t;
	ffkq_time_set(&t, -1);

	debug("entering kqueue loop");

	while (!s->stop) {
		int r = ffkq_wait(s->kq, ev, FF_COUNT(ev), t);
		if (r < 0) {
			if (fferr_last() == EINTR)
				continue;
			fatal("ffkq_wait: %E", fferr_last());
			return -1;
		}

		for (int i = 0;  i != r;  i++) {
			void *d = ffkq_event_data(&ev[i]);

			if (d == NULL) {
				srv_read_process(s);

			} else if (d == (void*)2) {
				ffkq_post_consume(s->postev);
				if (g->sig_reconfig) {
					g->sig_reconfig = 0;
					hosts_mod.sig(FDNS_SIG_RECONFIG);
				}
				if (g->sig_clear) {
					g->sig_clear = 0;
					cache_mod.sig(FDNS_SIG_CLEAR);
				}
				if (g->sig_task) {
					g->sig_task = 0;
					debug("dns: executing task %p %p", g->task_func, g->task_param);
					g->task_func(g->task_param);
				}

			} else if (d == (void*)3) {
				tmr_process(g);

			} else {
				ffkevent2 *kev = d;
				kev->func(kev->param);
			}
		}
	}

	debug("leaving kqueue loop");
	return 0;
}

int mods_sig(int sig)
{
	if (0 != cache_mod.sig(sig))
		return -1;
	if (0 != hosts_mod.sig(sig))
		return -1;
	if (0 != upstream_mod.sig(sig))
		return -1;
	return 0;
}

int dns_start(struct dnsmod *s)
{
	if (0 != srv_prepare(s))
		return -1;

	if (mods_sig(FDNS_SIG_START))
		return -1;

	srv_read_process(s);

	if (0 != srv_work(s))
		return -1;
	return 0;
}

void srv_init(struct dnsmod *s);

void srv_conf(fdns_core *_core, const ffconf_arg **conf_args, void **conf_obj)
{
	core = _core;
	dns_core.full_path = core->full_path;
	dns_core.time = core->time;
	dns_core.log = core->log;
	dns_core.log_level = core->log_level;

	g = ffmem_new(struct dnsmod);
	srv_init(g);

	*conf_args = dns_args;
	*conf_obj = &g->conf;
}

void srv_init(struct dnsmod *s)
{
	s->sk = FFSOCK_NULL;
	s->kq = FFKQ_NULL;
	ffsockaddr_set_ipv4(&s->conf.bind, NULL, 53);
	s->conf.block_aaaa = 1;
	s->conf.block_mode = BLOCK_MODE_LOCALIP;
	s->conf.block_ttl = 60;
}

int dns_sig(int sig)
{
	switch (sig) {
	case FDNS_SIG_INIT:
		break;

	case FDNS_SIG_START:
		return dns_start(g);

	case FDNS_SIG_STOP:
		g->stop = 1;
		ffkq_post(g->postev, (void*)2);
		break;

	case FDNS_SIG_RECONFIG:
		g->sig_reconfig = 1;
		ffkq_post(g->postev, (void*)2);
		break;

	case FDNS_SIG_CLEAR:
		g->sig_clear = 1;
		ffkq_post(g->postev, (void*)2);
		break;

	case FDNS_SIG_DESTROY:
		mods_sig(FDNS_SIG_DESTROY);
		srv_close(g);
		ffmem_free(g);  g = NULL;
		break;

	default:
		return -1;
	}
	return 0;
}

struct fdns_mod dns_mod = {
	"dns",
	srv_conf,
	dns_sig,
};


int dns_core_cmd(int cmd)
{
	return 0;
}

int dns_core_task(fdns_async_func func, void *param)
{
	g->task_func = func;
	g->task_param = param;
	g->sig_task = 1;
	ffkq_post(g->postev, (void*)2);
	debug("dns: added task %p %p", func, param);
	return 0;
}

int dns_core_timer(fdns_timer *t, int interval_msec, fdns_async_func func, void *param)
{
	if (interval_msec == 0) {
		fftimerqueue_remove(&g->timerq, t);
		debug("dns: removed timer %p [%L]", t, g->timerq.tree.len);
		return 0;
	}

	fftime now = fftime_monotonic();
	ffuint msec = fftime_to_msec(&now);
	fftimerqueue_add(&g->timerq, t, msec, interval_msec, func, param);
	debug("dns: added timer %p %d %p(%p) [%L]"
		, t, interval_msec, func, param, g->timerq.tree.len);
	return 0;
}

fdns_core dns_core = {
	0, 0,
	dns_core_cmd, NULL, dns_core_task, dns_core_timer, NULL, NULL,
};
