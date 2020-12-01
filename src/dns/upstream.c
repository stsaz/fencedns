/** fencedns: DNS upstream
2020, Simon Zolin */

#include <fencedns.h>
#include <dns/dnsmod.h>
#include <FF/net/url.h>
#include <FFOS/perf.h>
#include <ffbase/mem-print.h>

#define fatal(...)  ux->core->log(LOG_FATAL, __VA_ARGS__)
#define error(...)  ux->core->log(LOG_ERROR, __VA_ARGS__)
#define warning(...)  ux->core->log(LOG_WARNING, __VA_ARGS__)
#define info(...)  ux->core->log(LOG_INFO, __VA_ARGS__)
#define verbose(...)  ux->core->log(LOG_VERBOSE, __VA_ARGS__)
#define debug(...)  ux->core->log(LOG_DEBUG, __VA_ARGS__)


struct upstm;
void upstm_read_process(struct upstm *u);

struct upstream_conf {
	ffuint read_timeout;
};

struct upstm_ctx;
struct upstm {
	ffkevent2 kev;
	ffsockaddr addr;
	ffstr id;
	ffvec buf;
	ffsock sk;
	ffuint connected;
};

struct upstm_ctx {
	const fdns_core *core;
	struct upstream_conf conf;
	struct dnsmod *srv;
	ffvec servers; // struct upstm[]
	ffuint iserver;
	ffuint64 out_reqs, in_msgs, in_data, out_data;
};

static struct upstm_ctx *ux;

static int conf_server(ffconf_scheme *cs, void *obj, ffstr *val)
{
	struct upstm *u = ffvec_pushT(&ux->servers, struct upstm);
	ffmem_zero_obj(u);
	if (0 != ffsockaddr_fromstr(&u->addr, val->ptr, val->len, 53))
		return FFCONF_EBADVAL;
	ffstr_dup2(&u->id, val);
	return 0;
}

static const ffconf_arg upstream_args[] = {
	{ "server",	FFCONF_TSTR | FFCONF_FLIST, (ffsize)conf_server },
	{ "read_timeout_msec",	FFCONF_TINT32, FF_OFF(struct upstream_conf, read_timeout) },
	{},
};

static int upstm1_init(struct upstm *u, struct upstm_ctx *ux)
{
	ffvec_allocT(&u->buf, 4*1024, char);
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

	u->kev.func = (ffkevent_func)upstm_read_process;
	u->kev.param = u;
	if (0 != ffkq_attach_socket(ux->core->kq, u->sk, &u->kev, FFKQ_READ)) {
		fatal("upstream: ffkq_attach_socket: %E", fferr_last());
		return -1;
	}
	return 0;
}

static void upstm1_destroy(struct upstm *u)
{
	ffstr_free(&u->id);
	ffvec_free(&u->buf);
	ffsock_close(u->sk);  u->sk = FFSOCK_NULL;
}

static void upstm_free(struct upstm_ctx *ux)
{
	struct upstm *u;
	FFSLICE_WALK_T(&ux->servers, u, struct upstm){
		upstm1_destroy(u);
	}
	ffvec_free(&ux->servers);
	ffmem_free(ux);
}

struct upstm* upstm_next_srv(struct upstm_ctx *ux)
{
	struct upstm *u = ffslice_itemT(&ux->servers, ux->iserver, struct upstm);
	ux->iserver = (ux->iserver+1) % ux->servers.len;
	return u;
}

int upstm_send(struct client *c)
{
	struct upstm *u = upstm_next_srv(ux);
	int r;

	if (ux->srv == NULL)
		ux->srv = c->srv;

	if (!u->connected) {
		r = ffsock_connect(u->sk, &u->addr);
		if (r < 0) {
			error("upstream: %S: ffsock_connect: %E", &u->id, fferr_last());
			make_resp(c, NULL, FFDNS_SERVFAIL, "upstream-error");
			return DNS_FIN;
		}
		u->connected = 1;
		ux->core->task((fdns_async_func)upstm_read_process, u);
	}

	r = ffsock_send(u->sk, c->reqbuf.ptr, c->reqbuf.len, 0);
	if (r < 0) {
		error("upstream: %S: ffsock_send: %E", &u->id, fferr_last());
		make_resp(c, NULL, FFDNS_SERVFAIL, "upstream-error");
		return DNS_FIN;
	}
	ux->out_data += r;
	ux->out_reqs++;

	debug("upstream: %S: sent request %S (%u) %LB"
		, &u->id, &c->req.q.name, c->req.h.id, c->reqbuf.len);

	return DNS_CONTINUE;
}

static int resp_parse(struct upstm *u, struct dns_msg *resp)
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

static int upstm_read_process1(struct upstm *u)
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
		now = fftime_monotonic();
		fftime_sub(&now, &c->tstart);
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
	cli_conveyer(c);
	return 0;

end:
	dns_msg_destroy(&resp);
	return 0;
}

void upstm_read_process(struct upstm *u)
{
	for (;;) {
		int r = upstm_read_process1(u);
		if (r < 0)
			break;
	}
}

static void upstm_on_timeout(void *param)
{
	struct client *c = param;
	c->upstm_timeout = 1;
	cli_conveyer(c);
}

int upstm_recv(struct client *c)
{
	if (c->upstm_timeout) {
		warning("upstream: read timed out");
		make_resp(c, NULL, FFDNS_SERVFAIL, "upstream-error");
		return DNS_FIN;
	}

	if (c->respbuf.len == 0) {
		ux->core->timer(&c->tmr_upstm_recv, -(int)ux->conf.read_timeout, upstm_on_timeout, c);
		// waiting for the upstream socket to signal
		return DNS_ASYNC;
	}

	return DNS_CONTINUE;
}

static void upstream_conf(fdns_core *core, const ffconf_arg **conf_args, void **conf_obj)
{
	ux = ffmem_new(struct upstm_ctx);
	ux->core = core;
	ux->conf.read_timeout = 1000;

	*conf_args = upstream_args;
	*conf_obj = &ux->conf;
}

static int upstream_sig(int sig)
{
	switch (sig) {
	case FDNS_SIG_START: {
		struct upstm *u;
		FFSLICE_WALK_T(&ux->servers, u, struct upstm) {
			if (0 != upstm1_init(u, ux)) {
				return -1;
			}
		}
		break;
	}

	case FDNS_SIG_DESTROY:
		upstm_free(ux);
		ux = NULL;
		break;
	}
	return 0;
}

struct fdns_mod upstream_mod = {
	"upstream",
	upstream_conf, upstream_sig,
};
