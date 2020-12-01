/** fencedns: client processing
2020, Simon Zolin */

#include <fencedns.h>
#include <dns/dnsmod.h>
#include <FFOS/perf.h>
#include <FFOS/timer.h>
#include <ffbase/vector.h>
#include <ffbase/mem-print.h>
#include <ffbase/map.h>

static fdns_core *core;

#define fatal(...)  core->log(LOG_FATAL, __VA_ARGS__)
#define error(...)  core->log(LOG_ERROR, __VA_ARGS__)
#define warning(...)  core->log(LOG_WARNING, __VA_ARGS__)
#define info(...)  core->log(LOG_INFO, __VA_ARGS__)
#define verbose(...)  core->log(LOG_VERBOSE, __VA_ARGS__)
#define debug(...)  core->log(LOG_DEBUG, __VA_ARGS__)

#define cli_warning(c, fmt, ...)  core->log(LOG_WARNING, "%S: " fmt, &(c)->uid, ##__VA_ARGS__)
#define cli_verbose(c, fmt, ...)  core->log(LOG_VERBOSE, "%S: " fmt, &(c)->uid, ##__VA_ARGS__)
#define cli_debug(c, fmt, ...)  core->log(LOG_DEBUG, "%S: " fmt, &(c)->uid, ##__VA_ARGS__)

struct dns_conf {
	ffsockaddr bind;
	ffbyte block_aaaa;
	ffuint block_ttl;
	ffuint block_mode; // enum BLOCK_MODE
};

struct dnsmod {
	struct dns_conf conf;

	ffvec inbuf;
	ffuint client_uid;

	fftimer timer_fd;
	fftimerqueue timerq;

	fdns_async_func task_func;
	void *task_param;

	ffkq kq;
	ffsock sk;
	ffmap clients; // qid -> client*
	ffuint64 in_reqs, in_data, out_data;

	ffkq_postevent postev;
	ffuint stop;
	ffuint sig_reconfig;
	ffuint sig_clear;
	ffuint sig_task;
};
fdns_core dns_core;

#include <dns/block.h>

void client_free(struct client *c)
{
	dns_core.timer(&c->tmr_upstm_recv, 0, NULL, NULL);
	dns_msg_destroy(&c->req);
	dns_msg_destroy(&c->resp);
	ffstr_free(&c->reqbuf);
	ffvec_free(&c->respbuf);
	ffmem_free(c);
}

void make_resp(struct client *c, const ffip6 *ip, ffuint rcode, const char *status)
{
	ffvec resp = {};
	ffvec_allocT(&resp, FFDNS_MAXMSG, char);
	char *rr = resp.ptr;
	ffdns_header h = {};
	h.id = c->req.h.id;
	h.response = 1;
	h.rcode = rcode;
	h.recursion_available = 1;
	h.questions = 1;
	if (ip != NULL)
		h.answers = 1;
	resp.len = ffdns_header_write(resp.ptr, resp.cap, &h);

	resp.len += ffdns_question_write(rr + resp.len, ffvec_unused(&resp), &c->req.q);

	if (ip != NULL) {
		ffdns_answer a;
		a.name = c->req.q.name;
		a.type = c->req.q.type;
		a.clas = c->req.q.clas;
		a.ttl = c->srv->conf.block_ttl;
		if (ffip6_v4mapped(ip))
			ffstr_set(&a.data, ffip6_tov4(ip), 4);
		else
			ffstr_set(&a.data, ip, 16);
		resp.len += ffdns_answer_write(rr + resp.len, ffvec_unused(&resp), &a);
	}

	c->respbuf = resp;
	c->status = status;
}

int cli_process(struct client *c)
{
	c->tstart = fftime_monotonic();

	ffuint port = 0;
	ffslice ip = ffsockaddr_ip_port(&c->peer, &port);
	char ipstr[FFIP6_STRLEN+1];
	if (ip.len == 4)
		ffip4_tostrz(ip.ptr, ipstr, sizeof(ipstr));
	else
		ffip6_tostrz(ip.ptr, ipstr, sizeof(ipstr));
	cli_debug(c, "client: received %u bytes from %s:%u"
		, c->reqbuf.len, ipstr, port);

	if (dns_core.log_level >= LOG_DEBUG) {
		ffstr ss = ffmem_print(c->reqbuf.ptr, c->reqbuf.len, 0);
		cli_debug(c, "client: [%L]\n%S", c->reqbuf.len, &ss);
		ffstr_free(&ss);
	}

	if (c->req.h.response) {
		cli_debug(c, "c->req.h.response");
		return DNS_CLOSE;
	}

	if (0 > ffdns_header_read(&c->req.h, c->reqbuf)) {
		cli_warning(c, "ffdns_header_read");
		make_resp(c, NULL, FFDNS_FORMERR, "error");
		return DNS_FIN;
	}

	if (0 > ffdns_question_read(&c->req.q, c->reqbuf)){
		cli_warning(c, "ffdns_question_read");
		make_resp(c, NULL, FFDNS_FORMERR, "error");
		return DNS_FIN;
	}

	if (c->req.q.clas != FFDNS_IN) {
		cli_warning(c, "unknown class %u in question", c->req.q.clas);
		return DNS_CLOSE;
	}

	ffstr_lower((ffstr*)&c->req.q.name);
	cli_debug(c, "client: request %u %S (%u)"
		, c->req.q.type, &c->req.q.name, c->req.h.id);

	srv_addclient(c->srv, c->req.h.id, c);
	return DNS_CONTINUE;
}

int cli_reply(struct client *c)
{
	if (dns_core.log_level >= LOG_DEBUG) {
		ffstr ss = ffmem_print(c->respbuf.ptr, c->respbuf.len, 0);
		cli_debug(c, "client: response: [%L]\n%S", c->respbuf.len, &ss);
		ffstr_free(&ss);
	}

	int r = ffsock_sendto(c->srv->sk, c->respbuf.ptr, c->respbuf.len, 0, &c->peer);
	if (r < 0) {
		cli_warning(c, "ffsock_sendto: %E", fferr_last());
	}
	c->srv->out_data += c->respbuf.len;

	ffuint port = 0;
	ffslice ip = ffsockaddr_ip_port(&c->peer, &port);
	char ipstr[FFIP6_STRLEN+1];
	if (ip.len == 4)
		ffip4_tostrz(ip.ptr, ipstr, sizeof(ipstr));
	else
		ffip6_tostrz(ip.ptr, ipstr, sizeof(ipstr));

	cli_verbose(c, "client: %s: response: %u %S (%u) %LB (%s)"
		, ipstr, c->req.q.type, &c->req.q.name, c->req.h.id, c->reqbuf.len, c->status);

	return DNS_CONTINUE;
}

typedef int (*cli_filter)(struct client *c);

int cli_timeout(struct client *c)
{
	return DNS_CONTINUE;
}

static const cli_filter filters[] = {
	cli_process,
	block_aaaa,
	hosts_process,
	cache_process_req,
	upstm_send,
	cli_timeout,
	upstm_recv,
	cache_process_resp,
	cli_reply,
};

void cli_conveyer(struct client *c)
{
	for (;;) {
		if (c->cur_filter == FF_COUNT(filters))
			break;

		cli_filter f = filters[c->cur_filter];
		int r = f(c);
		switch (r) {
		case DNS_CONTINUE:
			c->cur_filter++;
			break;

		case DNS_ASYNC:
			cli_debug(c, "client: filter returned DNS_ASYNC");
			return;

		case DNS_FIN:
			c->cur_filter = FF_COUNT(filters) - 1;
			break;

		case DNS_CLOSE:
			goto end;

		default:
			FF_ASSERT(0);
			break;
		}
	}

end:
	srv_rmclient(c->srv, c->req.h.id, c);
	client_free(c);
}
