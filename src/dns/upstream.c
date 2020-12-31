/** fencedns: DNS upstream
2020, Simon Zolin */

#include <fencedns.h>
#include <dns/dnsmod.h>
#include <FF/net/url.h>
#include <ffbase/mem-print.h>

#define fatal(...)  ux->core->log(LOG_FATAL, __VA_ARGS__)
#define error(...)  ux->core->log(LOG_ERROR, __VA_ARGS__)
#define warning(...)  ux->core->log(LOG_WARNING, __VA_ARGS__)
#define info(...)  ux->core->log(LOG_INFO, __VA_ARGS__)
#define verbose(...)  ux->core->log(LOG_VERBOSE, __VA_ARGS__)
#define debug(...)  ux->core->log(LOG_DEBUG, __VA_ARGS__)

struct upconf {
	ffuint read_timeout;
	ffuint send_attempts;
};

struct upstream {
	ffkevent2 kev;
	ffsockaddr addr;
	ffstr id;
	ffvec buf;
	ffsock sk;
	ffuint connected;
};

struct upctx {
	const fdns_core *core;
	struct upconf upconf;
	struct dnsmod *srv;
	ffvec servers; // struct upstream[]
	ffuint iserver;
	ffuint64 out_reqs, in_msgs, in_data, out_data;
};
static struct upctx *ux;

static int conf_server(ffconf_scheme *cs, void *obj, ffstr *val)
{
	struct upstream *u = ffvec_pushT(&ux->servers, struct upstream);
	ffmem_zero_obj(u);
	if (0 != ffsockaddr_fromstr(&u->addr, val->ptr, val->len, 53))
		return FFCONF_EBADVAL;
	ffstr_dup2(&u->id, val);
	return 0;
}

static const ffconf_arg upstream_args[] = {
	{ "server",	FFCONF_TSTR | FFCONF_FLIST, (ffsize)conf_server },
	{ "read_timeout_msec",	FFCONF_TINT32, FF_OFF(struct upconf, read_timeout) },
	{ "send_attempts",	FFCONF_TINT32, FF_OFF(struct upconf, send_attempts) },
	{},
};

void upst_read_input(struct upstream *u);

static int upst_sock_init(struct upstream *u, struct upctx *ux)
{
	u->sk = ffsock_create_udp(AF_INET, FFSOCK_NONBLOCK);
	if (u->sk == FFSOCK_NULL) {
		fatal("upstream: ffsock_create_udp: %E", fferr_last());
		return -1;
	}

	ffsockaddr addr;
	ffsockaddr_set_ipv4(&addr, NULL, 0);
	if (0 != ffsock_bind(u->sk, &addr)) {
		fatal("upstream: ffsock_bind: %E", fferr_last());
		return -1;
	}

	u->kev.func = (ffkevent_func)upst_read_input;
	u->kev.param = u;
	if (0 != ffkq_attach_socket(ux->core->kq, u->sk, &u->kev, FFKQ_READ)) {
		fatal("upstream: ffkq_attach_socket: %E", fferr_last());
		return -1;
	}
	return 0;
}

static int upst_init(struct upstream *u, struct upctx *ux)
{
	u->sk = FFSOCK_NULL;
	ffvec_allocT(&u->buf, 4*1024, char);
	return upst_sock_init(u, ux);
}

static void upst_destroy(struct upstream *u)
{
	ffstr_free(&u->id);
	ffvec_free(&u->buf);
	ffsock_close(u->sk);  u->sk = FFSOCK_NULL;
}

static void upctx_free(struct upctx *ux)
{
	struct upstream *u;
	FFSLICE_WALK(&ux->servers, u){
		upst_destroy(u);
	}
	ffvec_free(&ux->servers);
	ffmem_free(ux);
}

/** Send request */
static int upst_send_req(struct upstream *u, struct client *c)
{
	int r;
	int was_connected = u->connected;

	if (!u->connected) {
		r = ffsock_connect(u->sk, &u->addr);
		if (r < 0) {
			error("upstream: %S: ffsock_connect: %E", &u->id, fferr_last());
			return DNS_FIN;
		}
		u->connected = 1;
		ux->core->task((fdns_async_func)upst_read_input, u);
	}

	r = ffsock_send(u->sk, c->reqbuf.ptr, c->reqbuf.len, 0);
	if (r < 0) {
		if (was_connected) {
			ffsock_close(u->sk);  u->sk = FFSOCK_NULL;
			u->connected = 0;
			if (DNS_CONTINUE != upst_sock_init(u, ux)) {
				return DNS_FIN;
			}
			return upst_send_req(u, c);
		}
		error("upstream: %S: ffsock_send: %E", &u->id, fferr_last());
		return DNS_FIN;
	}
	ux->out_data += r;
	ux->out_reqs++;

	debug("upstream: %S: sent request %S (%u) %LB"
		, &u->id, &c->req.q.name, c->req.h.id, c->reqbuf.len);
	c->upstm = u;
	return DNS_CONTINUE;
}

/** Get next server (round-robin) */
struct upstream* upctx_next_srv(struct upctx *ux)
{
	struct upstream *u = ffslice_itemT(&ux->servers, ux->iserver, struct upstream);
	ux->iserver = (ux->iserver+1) % ux->servers.len;
	return u;
}

/** Select server and send request */
int upstm_send(struct client *c)
{
	c->upstream_attempts = ux->upconf.send_attempts;
	struct upstream *u = upctx_next_srv(ux);

	if (ux->srv == NULL)
		ux->srv = c->srv;

	int r = upst_send_req(u, c);
	if (r == DNS_FIN)
		cl_make_resp(c, FFDNS_SERVFAIL, "upstream-error");
	return r;
}

/** Parse response */
static int resp_parse(struct upstream *u, struct dns_msg *resp)
{
	resp->ttl = -1;
	int r;

	if (0 > (r = ffdns_header_read(&resp->h, resp->data))) {
		warning("upstream: %S: invalid header data", &u->id);
		return -1;
	}
	ffuint off = r;
	if (0 > (r = ffdns_question_read(&resp->q, resp->data))) {
		warning("upstream: %S: invalid question data", &u->id);
		return -1;
	}
	off += r;

	for (ffuint ia = 0;  ia != resp->h.answers;  ia++) {
		ffdns_answer *a = ffvec_pushT(&resp->answers, ffdns_answer);
		ffmem_zero_obj(a);
		if (0 > (r = ffdns_answer_read(a, resp->data, off))) {
			warning("upstream: %S: invalid answer data", &u->id);
			return -1;
		}
		off += r;
		resp->ttl = ffmin(resp->ttl, a->ttl);
	}

	return 0;
}

/*
. read, parse response
. find the associated client; proceed with its filter chain */
static int upst_read_process(struct upstream *u)
{
	struct dns_msg resp = {};
	int r = ffsock_recv(u->sk, u->buf.ptr, u->buf.cap, 0);
	if (r < 0) {
		if (!fferr_again(fferr_last()))
			warning("upstream: %S: ffsock_recv: %E", &u->id, fferr_last());
		return -1;
	}
	ux->in_data += r;
	ux->in_msgs++;
	ffstr_set(&resp.data, u->buf.ptr, r);
	debug("upstream: %S: received %u bytes", &u->id, r);

	if (ux->core->log_level >= LOG_DEBUG) {
		ffstr ss = ffmem_print(resp.data.ptr, resp.data.len, 0);
		debug("upstream: %S: [%L]\n%S", &u->id, resp.data.len, &ss);
		ffstr_free(&ss);
	}

	if (0 > resp_parse(u, &resp))
		return -1;

	struct client *c = srv_findclient(ux->srv, resp.h.id);

	fftime now = {};
	if (c != NULL) {
		now = ux->core->time(FDNS_TIME_MONO, NULL);
		fftime_sub(&now, &c->tstart);
		ux->core->timer(&c->tmr_upstm_recv, 0, NULL, 0);
	}
	ffuint tmsec = fftime_to_msec(&now);
	info("upstream: %S: %u %S (%u) opcode:%d rcode:%d a:%u ns:%u ad:%u %LB %ums [total:%U/%U/%U]"
		, &u->id
		, resp.q.type, &resp.q.name, resp.h.id, resp.h.opcode, resp.h.rcode
		, resp.h.answers, resp.h.nss, resp.h.additionals
		, resp.data.len
		, tmsec
		, ux->in_data, ux->out_data, ux->out_reqs);

	if (c == NULL) {
		goto end;
	}

	c->resp = resp;
	c->status = "upstream";
	ffvec_add2T(&c->respbuf, &resp.data, char);
	cl_conveyer(c);
	return 0;

end:
	dns_msg_destroy(&resp);
	return 0;
}

void upst_read_input(struct upstream *u)
{
	for (;;) {
		int r = upst_read_process(u);
		if (r < 0)
			break;
	}
}

static void upstm_timeout(struct client *c)
{
	struct upstream *u = c->upstm;

	warning("upstream: %S: %u %S: read timed out"
		, &u->id, c->req.q.type, &c->req.q.name);

	c->upstream_attempts--;
	if (c->upstream_attempts != 0) {
		u = upctx_next_srv(ux);
		if (DNS_CONTINUE != upst_send_req(u, c)) {
			goto end;
		}
		ux->core->timer(&c->tmr_upstm_recv, -(int)ux->upconf.read_timeout, (fdns_async_func)upstm_timeout, c);
		// waiting for the upstream socket to signal
		return;
	}

end:
	c->upstm_timeout = 1;
	cl_conveyer(c);
}

int upstm_recv(struct client *c)
{
	if (c->upstm_timeout) {
		cl_make_resp(c, FFDNS_SERVFAIL, "upstream-error");
		return DNS_FIN;
	}

	if (c->respbuf.len == 0) {
		ux->core->timer(&c->tmr_upstm_recv, -(int)ux->upconf.read_timeout, (fdns_async_func)upstm_timeout, c);
		// waiting for the upstream socket to signal
		return DNS_ASYNC;
	}

	return DNS_CONTINUE;
}

static void upstream_conf(fdns_core *core, const ffconf_arg **conf_args, void **conf_obj)
{
	ux = ffmem_new(struct upctx);
	ux->core = core;
	ux->upconf.read_timeout = 300;
	ux->upconf.send_attempts = 3;

	*conf_args = upstream_args;
	*conf_obj = &ux->upconf;
}

static int upctx_start(struct upctx *ux)
{
	struct upstream *u;
	FFSLICE_WALK(&ux->servers, u) {
		if (0 != upst_init(u, ux)) {
			return -1;
		}
	}
	return 0;
}

static int upstream_sig(int sig)
{
	switch (sig) {
	case FDNS_SIG_START:
		return upctx_start(ux);

	case FDNS_SIG_DESTROY:
		upctx_free(ux);
		ux = NULL;
		break;
	}
	return 0;
}

struct fdns_mod upstream_mod = {
	"upstream",
	upstream_conf, upstream_sig,
};
