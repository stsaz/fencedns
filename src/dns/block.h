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
		cli_verbose(c, "client: response: %u %S (%u) %LB (%s)"
			, c->req.q.type, &c->req.q.name, c->req.h.id, c->reqbuf.len, status);
		return DNS_CLOSE;
	}

	make_resp(c, ip_ptr, rcode, status);
	return DNS_FIN;
}

int block_aaaa(struct client *c)
{
	if (c->req.q.type == 28 && c->srv->conf.block_aaaa) {
		cli_debug(c, "client: blocking AAAA request");
		make_resp(c, NULL, FFDNS_NOERROR, "aaaa-blocked");
		return DNS_FIN;
	}
	return DNS_CONTINUE;
}
