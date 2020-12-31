/** fencedns: DNS stuff
2020, Simon Zolin */

#pragma once

#include <fencedns.h>
#include <FF/net/ipaddr.h>
#include <FF/net/dns.h>
#include <FFOS/socket.h>

struct dns_msg {
	ffstr data;
	ffuint ttl;
	ffdns_header h;
	ffdns_question q;
	ffvec answers; // ffdns_answer[]
};

static inline void dns_msg_destroy(struct dns_msg *msg)
{
	ffdns_question_destroy(&msg->q);
	ffdns_answer *a;
	FFSLICE_WALK_T(&msg->answers, a, ffdns_answer) {
		ffdns_answer_destroy(a);
	}
	ffvec_free(&msg->answers);
}

struct dnsmod;
struct client {
	struct dnsmod *srv;
	void *upstm;
	ffuint upstream_attempts;

	char uid_s[32];
	ffstr uid;
	struct dns_msg req;
	struct dns_msg resp;
	ffsockaddr peer;
	fftime tstart;
	ffstr reqbuf;
	ffvec respbuf;
	ffuint cur_filter;
	fdns_timer tmr_upstm_recv;
	ffuint upstm_timeout :1;
	ffuint in_list :1;
	const char *status;
};

void srv_addclient(struct dnsmod *s, ffuint id, struct client *c);
void srv_rmclient(struct dnsmod *s, ffuint id, struct client *c);
struct client* srv_findclient(struct dnsmod *s, ffuint id);
void cl_make_resp(struct client *c, ffuint rcode, const char *status);
void cl_make_resp_ip(struct client *c, ffuint rcode, const ffip6 *ipa, ffuint ttl, const char *status);
int block_resp(struct client *c, const char *status);
void cl_conveyer(struct client *c);

int upstm_send(struct client *c);
int upstm_recv(struct client *c);

int cache_process_req(struct client *c);
int cache_process_resp(struct client *c);

int hosts_process(struct client *c);

enum DNS_R {
	DNS_CONTINUE,
	DNS_FIN,
	DNS_CLOSE,
	DNS_ASYNC,
};

extern struct fdns_mod cache_mod;
extern struct fdns_mod hosts_mod;
extern struct fdns_mod upstream_mod;
