/** fencedns: blocking
2020, Simon Zolin */

enum BLOCK_MODE {
	BLOCK_MODE_NXDOMAIN,
	BLOCK_MODE_REFUSED,
	BLOCK_MODE_EMPTY,
	BLOCK_MODE_NULLIP,
	BLOCK_MODE_LOCALIP,
	BLOCK_MODE_DROP,
};

/** Prepare response to a client according to configuration */
int block_resp(struct client *c, const char *status)
{
	int rcode = FFDNS_NOERROR;
	ffip6 *ip_ptr = NULL, ip;
	const ffdns_question *q = &c->req.q;

	switch (c->srv->conf.block_mode) {

	case BLOCK_MODE_NXDOMAIN:
		rcode = FFDNS_NXDOMAIN;
		break;

	case BLOCK_MODE_REFUSED:
		rcode = FFDNS_REFUSED;
		break;

	case BLOCK_MODE_EMPTY:
		break;

	case BLOCK_MODE_NULLIP:
		if (q->type == FFDNS_A) {
			// 0.0.0.0
			ffip6_v4mapped_set(&ip, (ffip4*)"\x00\x00\x00\x00");
			ip_ptr = &ip;
		} else if (q->type == FFDNS_AAAA) {
			// ::
			ffmem_copy(&ip, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
			ip_ptr = &ip;
		}
		break;

	case BLOCK_MODE_LOCALIP:
		if (q->type == FFDNS_A) {
			// 127.0.0.1
			ffip6_v4mapped_set(&ip, (ffip4*)"\x7f\x00\x00\x01");
			ip_ptr = &ip;
		} else if (q->type == FFDNS_AAAA) {
			// ::1
			ffmem_copy(&ip, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16);
			ip_ptr = &ip;
		}
		break;

	case BLOCK_MODE_DROP:
		cl_verbose(c, "client: response: %u %S (%u) %LB (%s)"
			, c->req.q.type, &c->req.q.name, c->req.h.id, c->reqbuf.len, status);
		return DNS_CLOSE;
	}

	cl_make_resp_ip(c, rcode, ip_ptr, c->srv->conf.block_ttl, status);
	return DNS_FIN;
}

/** Respond to AAAA requests with an empty answer */
int block_aaaa(struct client *c)
{
	if (c->req.q.type == 28 && c->srv->conf.block_aaaa) {
		cl_debug(c, "client: blocking AAAA request");
		cl_make_resp(c, FFDNS_NOERROR, "aaaa-blocked");
		return DNS_FIN;
	}
	return DNS_CONTINUE;
}
