/** fencedns: DNS hosts
2020, Simon Zolin */

#include <fencedns.h>
#include <dns/dnsmod.h>
#include <ffbase/vector.h>
#include <ffbase/map.h>
#include <ffbase/string.h>
#include <FF/net/url.h>

#define error(...)  hx->core->log(LOG_ERROR, __VA_ARGS__)
#define warning(...)  hx->core->log(LOG_WARNING, __VA_ARGS__)
#define info(...)  hx->core->log(LOG_INFO, __VA_ARGS__)
#define verbose(...)  hx->core->log(LOG_VERBOSE, __VA_ARGS__)
#define debug(...)  hx->core->log(LOG_DEBUG, __VA_ARGS__)

struct conf {
	ffuint file_refresh_period_sec;
	ffuint rewrite_ttl;
};

struct source {
	ffstr name;
	fftime mtime;
	ffvec data; // char[]
	ffvec entries; // struct entry[]
	ffvec entries_ip; // struct entry_ip[]
};

struct hosts_ctx {
	struct conf conf;
	const fdns_core *core;
	ffvec sources; // struct source[]
	ffmap hosts; // host -> struct entry*
	ffuint misses, hits;
	fdns_timer tmr_refresh;
};

static struct hosts_ctx *hx;

enum TYPE {
	T_BLOCK = 1, // block domain and its subdomains
	T_PASS = 2, // pass domain and its subdomains
	T_IPV4 = 4, // assign IPv4 address to an exact domain
	T_IPV6 = 0x10, // assign IPv6 address to an exact domain
};

#pragma pack(push)
#pragma pack(4)
struct entry {
	const char *host_ptr; // -> source.data
	ffushort host_len;
	ffushort type; // enum TYPE
};

struct entry_ip {
	const char *host_ptr;
	ffushort host_len;
	ffushort type; // enum TYPE
	ffbyte ip[16]; // for T_IPV4 and T_IPV6
};
#pragma pack(pop)

static void source_add(struct hosts_ctx *hx, ffstr *fn);

static int conf_file(ffconf_scheme *cs, void *obj, ffstr *val)
{
	struct conf *conf = obj;
	struct hosts_ctx *hx = FF_STRUCTPTR(struct hosts_ctx, conf, conf);
	ffstr full = hx->core->full_path(*val);
	source_add(hx, &full);
	return 0;
}

static const ffconf_arg hosts_args[] = {
	{ "file",	FFCONF_TSTR, (ffsize)conf_file },
	{ "file_refresh_period_sec",	FFCONF_TINT32, FF_OFF(struct conf, file_refresh_period_sec) },
	{ "rewrite_ttl",	FFCONF_TINT32, FF_OFF(struct conf, rewrite_ttl) },
	{},
};

static void hosts_clear(struct hosts_ctx *hx)
{
	ffmap_free(&hx->hosts);
}

static void hosts_free(struct hosts_ctx *hx)
{
	hosts_clear(hx);

	struct source *src;
	FFSLICE_WALK_T(&hx->sources, src, struct source) {
		ffstr_free(&src->name);
		ffvec_free(&src->data);
		ffvec_free(&src->entries);
		ffvec_free(&src->entries_ip);
	}
	ffvec_free(&hx->sources);
	ffmem_free(hx);
}

static ffstr entry_host(const struct entry *ent)
{
	ffstr host = FFSTR_INITN(ent->host_ptr, ent->host_len);
	return host;
}

static int map_keyeq(void *opaque, const void *key, ffsize keylen, void *val)
{
	(void)opaque;
	struct entry *ent = (struct entry*)val;
	ffstr host = entry_host(ent);
	return ffstr_eq(&host, key, keylen);
}

/** Add existing hosts to a map */
static int source_addhosts(struct hosts_ctx *hx, struct source *src)
{
	if (0 != ffmap_grow(&hx->hosts, src->entries.len))
		return -1;

	struct entry *ent, *he2;
	FFSLICE_WALK_T(&src->entries, ent, struct entry) {
		ffstr host = entry_host(ent);
		ffuint hash = ffmap_hash(host.ptr, host.len);
		he2 = ffmap_find_hash(&hx->hosts, hash, host.ptr, host.len, NULL);
		if (he2 != NULL) {
			verbose("hosts: overwriting the existing entry for %S", &host);
			ffmap_rm_hash(&hx->hosts, hash, he2);
		}

		ffmap_add_hash(&hx->hosts, hash, ent);
	}

	struct entry_ip *ent_ip;
	FFSLICE_WALK_T(&src->entries_ip, ent_ip, struct entry_ip) {
		ffstr host = entry_host((struct entry*)ent_ip);
		ffuint hash = ffmap_hash(host.ptr, host.len);
		he2 = ffmap_find_hash(&hx->hosts, hash, host.ptr, host.len, NULL);
		if (he2 != NULL) {
			verbose("hosts: overwriting the existing entry for %S", &host);
			ffmap_rm_hash(&hx->hosts, hash, he2);
		}

		ffmap_add_hash(&hx->hosts, hash, ent_ip);
	}

	info("hosts: added %L from %s"
		, src->entries.len, src->name.ptr);

	return 0;
}

/** Count the number of hosts */
static ffuint source_count_hosts(const ffstr *data, ffuint *_n_ip)
{
	ffuint n = 0, n_ip = 0;
	ffstr d = *data, ln, host, skip = FFSTR_INITZ(" \t\r");

	while (d.len != 0) {
		ffstr_splitby(&d, '\n', &ln, &d);
		int type = -1;

		while (ln.len != 0) {

			ffstr_skipany(&ln, &skip);
			if (ln.len == 0)
				break;
			if (ln.ptr[0] == '#')
				break; // skip comment
			if (type < 0 && ln.ptr[0] == '!')
				break; // skip comment

			ffstr_splitbyany(&ln, " \t", &host, &ln);

			if (type < 0) {
				ffip4 ipaddr;
				if (0 == ffip4_parse(&ipaddr, host.ptr, host.len)) {
					type = T_IPV4;
					continue;
				}
				type = T_BLOCK;
			}

			n++;
			if (type == T_IPV4)
				n_ip++;
		}
	}

	*_n_ip = n_ip;
	return n;
}

/** Read hosts from file and add them to a map
File syntax:
# comment
! comment
([+]BASE_HOST)... # comment
||BASE_HOST^
IP EXACT_HOST...
*/
static int source_read(struct hosts_ctx *hx, struct source *src)
{
	fftime tstart = hx->core->time(2, NULL);
	int rc = -1;
	ffuint n = 0, n_ip;
	ffvec data = {};
	ffvec entries = {};
	ffvec entries_ip = {};
	debug("hosts: reading %s", src->name.ptr);
	if (0 != fffile_readwhole(src->name.ptr, &data, -1)) {
		error("hosts: file read: %S %E", &src->name, fferr_last());
		goto end;
	}

	n = source_count_hosts((ffstr*)&data, &n_ip);
	debug("hosts: source_count_hosts:%u", n);
	if (0 != ffmap_grow(&hx->hosts, n))
		goto end;
	ffvec_allocT(&entries, n - n_ip, struct entry);
	ffvec_allocT(&entries_ip, n_ip, struct entry_ip);
	n = 0;

	ffstr d, ln, host, skip = FFSTR_INITZ(" \t\r");
	ffstr_set2(&d, &data);

	while (d.len != 0) {
		ffstr_splitby(&d, '\n', &ln, &d);
		int type = -1;
		ffip4 ipaddr;

		while (ln.len != 0) {

			ffstr_skipany(&ln, &skip);
			if (ln.len == 0)
				break;
			if (ln.ptr[0] == '#')
				break; // skip comment
			if (type < 0 && ln.ptr[0] == '!')
				break; // skip comment

			ffstr_splitbyany(&ln, " \t", &host, &ln);

			if (type < 0) {

				if (host.len > 3
					&& host.ptr[0] == '|' && host.ptr[1] == '|' && host.ptr[host.len-1] == '^') {

					type = 0x0100 | T_BLOCK;
					host.ptr += 2;
					host.len -= 3;

				} else if (0 == ffip4_parse(&ipaddr, host.ptr, host.len)) {
					type = T_IPV4;
					continue; // the first field is an IP

				} else {
					type = T_BLOCK;
					if (host.ptr[0] == '+') {
						ffstr_shift(&host, 1);
						type = T_PASS;
					}
				}

			} else if (type == T_IPV4) {

			} else if (type == T_BLOCK) {
				if (host.ptr[0] == '+') {
					ffstr_shift(&host, 1);
					type = T_PASS;
				}

			} else if (type == T_PASS) {
				if (host.ptr[0] != '+') {
					type = T_BLOCK;
				}

			} else {
				verbose("hosts: unexpected value %S", &host);
				break;
			}

			if (0 > ffurl_isdomain(host.ptr, host.len)) {
				verbose("hosts: invalid host name: %S", &host);
				continue;
			}

			ffstr_lower(&host);

			ffuint hash = ffmap_hash(host.ptr, host.len);
			struct entry *old, *ent;
			old = ffmap_find_hash(&hx->hosts, hash, host.ptr, host.len, NULL);
			if (old != NULL) {
				ffmap_rm_hash(&hx->hosts, hash, old);

				if (type == T_IPV4 || (old->type & T_IPV4)) {
					ent = (struct entry*)ffvec_pushT(&entries_ip, struct entry_ip);
					if (type == T_IPV4) {
						ent->type = old->type | T_IPV4;
					} else {
						struct entry_ip *old_ip = (struct entry_ip*)old;
						struct entry_ip *ent_ip = (struct entry_ip*)ent;
						*(ffuint*)ent_ip->ip = *(ffuint*)old_ip->ip;
						ent->type = T_IPV4 | (type & 0xff);
					}
					verbose("hosts: merging with the existing entry for %S: %u"
						, &host, ent->type);
				} else {
					ent = ffvec_pushT(&entries, struct entry);
					ent->type = type & 0xff;
					verbose("hosts: overwriting the existing entry for %S: %u"
						, &host, ent->type);
				}

			} else {
				if (type == T_IPV4) {
					ent = (struct entry*)ffvec_pushT(&entries_ip, struct entry_ip);
				} else {
					ent = ffvec_pushT(&entries, struct entry);
				}
				ent->type = type & 0xff;
			}

			ent->host_ptr = host.ptr;
			ent->host_len = host.len;
			if (type == T_IPV4) {
				struct entry_ip *ent_ip = (struct entry_ip*)ent;
				*(ffuint*)ent_ip->ip = *(ffuint*)&ipaddr;
			}

			ffmap_add_hash(&hx->hosts, hash, ent);
			n++;
			/* if () {
				debug("hosts: %S [%L]"
					, &host, hx->hosts.len);
			} else {
				debug("hosts: %S -> %S [%L]"
					, &host, &ip, hx->hosts.len);
			} */
		}
	}

	fftime tstop = hx->core->time(2, NULL);
	fftime_sub(&tstop, &tstart);
	info("hosts: added %u from %s (%ums)"
		, n, src->name.ptr, (ffuint)fftime_to_msec(&tstop));
	if (hx->core->log_level >= LOG_DEBUG)
		_ffmap_stats(&hx->hosts, 0);

	ffvec_free(&src->data);
	ffvec_free(&src->entries);
	ffvec_free(&src->entries_ip);
	src->data = data;
	src->entries = entries;
	src->entries_ip = entries_ip;
	fffileinfo fi;
	if (0 == fffile_info_path(src->name.ptr, &fi))
		src->mtime = fffileinfo_mtime(&fi);
	rc = 0;

end:
	if (rc != 0) {
		ffvec_free(&data);
		ffvec_free(&entries);
		ffvec_free(&entries_ip);
	}
	return 0;
}

/**
Return rule type;
  <0 if no match */
static int hosts_find(struct hosts_ctx *hx, const ffdns_question *q, ffip6 *ip)
{
	if (q->name.len <= 1)
		return 0;

	ffstr name;
	ffstr_set2(&name, &q->name);
	ffstr_rskipchar1(&name, '.');

	int subdomain_match = 0;
	struct entry *ent;
	for (;;) {
		ent = ffmap_find(&hx->hosts, name.ptr, name.len, NULL);
		if (ent != NULL) {
			// "127.0.0.1 host.com" must not match "sub.host.com"
			if (!(subdomain_match
				&& (ent->type == T_IPV4 || ent->type == T_IPV6)))
				break;
		}
		// "a.b.c" -> "b.c"
		if (0 > ffstr_splitby(&name, '.', NULL, &name))
			break;
		subdomain_match = 1;
	}
	if (ent == NULL) {
		hx->misses++;
		return -1;
	}

	int t = ent->type & (T_BLOCK | T_PASS);
	if (!subdomain_match && (ent->type & T_IPV4)) {
		if (q->type == FFDNS_A) {
			const struct entry_ip *ent_ip = (struct entry_ip*)ent;
			ffip6_v4mapped_set(ip, (ffip4*)ent_ip->ip);
		}
		t = T_IPV4;
	} else if (!subdomain_match && (ent->type & T_IPV6)) {
		if (q->type == FFDNS_AAAA) {
			const struct entry_ip *ent_ip = (struct entry_ip*)ent;
			ffmem_copy(ip, ent_ip->ip, 16);
		}
		t = T_IPV6;
	}

	debug("hosts: %S/%u matches %S"
		, &name, ent->type, &q->name);
	hx->hits++;

	return t;
}

static int hosts_read_sources(struct hosts_ctx *hx)
{
	ffmap_init(&hx->hosts, map_keyeq);
	struct source *src;
	FFSLICE_WALK_T(&hx->sources, src, struct source) {
		if (src->mtime.sec != 0) {
			source_addhosts(hx, src);
			continue;
		}

		source_read(hx, src);
	}

	ffsize total = 0;
	FFSLICE_WALK_T(&hx->sources, src, struct source) {
		total += src->data.len + src->entries.len * sizeof(struct entry);
	}
	info("hosts: total:%LB/%L"
		, total + hx->hosts.cap * sizeof(struct _ffmap_item), hx->hosts.len);
	return 0;
}

static void hosts_refresh(struct hosts_ctx *hx)
{
	debug("hosts: refreshing...");

	ffuint n = 0;
	struct source *src;
	FFSLICE_WALK_T(&hx->sources, src, struct source) {
		fffileinfo fi;
		if (0 != fffile_info_path(src->name.ptr, &fi))
			continue;
		fftime mtime = fffileinfo_mtime(&fi);
		if (fftime_cmp(&mtime, &src->mtime) <= 0)
			continue;

		fftime_null(&src->mtime);
		debug("hosts: file %s has been modified, reloading...", src->name.ptr);
		n++;
	}

	if (n == 0)
		return;

	hosts_clear(hx);
	hosts_read_sources(hx);
}

static void hosts_timer(void *param)
{
	struct hosts_ctx *s = param;
	hosts_refresh(s);
}

static void source_add(struct hosts_ctx *hx, ffstr *fn)
{
	struct source *src = ffvec_pushT(&hx->sources, struct source);
	ffmem_zero_obj(src);
	src->name = *fn;
	ffstr_null(fn);
}

int hosts_process(struct client *c)
{
	ffip6 ip = {};
	int t = hosts_find(hx, &c->req.q, &ip);
	if (t < 0 || t == T_PASS)
		return DNS_CONTINUE;

	if (t == T_BLOCK)
		return block_resp(c, "hosts-block");

	cl_make_resp_ip(c, FFDNS_NOERROR, &ip, hx->conf.rewrite_ttl, "hosts-rewrite");
	return DNS_FIN;
}

static void hosts_conf(fdns_core *core, const ffconf_arg **conf_args, void **conf_obj)
{
	hx = ffmem_new(struct hosts_ctx);
	hx->core = core;
	hx->conf.file_refresh_period_sec = 60;
	hx->conf.rewrite_ttl = 86400;

	*conf_args = hosts_args;
	*conf_obj = &hx->conf;
}

static int hosts_sig(int sig)
{
	switch (sig) {
	case FDNS_SIG_START:
		hosts_read_sources(hx);
		hx->core->timer(&hx->tmr_refresh, hx->conf.file_refresh_period_sec * 1000, hosts_timer, hx);
		break;

	case FDNS_SIG_RECONFIG:
		hosts_refresh(hx);
		break;

	case FDNS_SIG_DESTROY:
		hosts_free(hx);
		hx = NULL;
		break;
	}
	return 0;
}

struct fdns_mod hosts_mod = {
	"hosts",
	hosts_conf, hosts_sig,
};
