/** fencedns: config reader
2020, Simon Zolin */

#include <fencedns.h>

static int conf_mod(ffconf_scheme *cs, void *obj)
{
	struct fdns_mod *iface;
	if (ffsz_eq(cs->arg->name, "dns"))
		iface = &dns_mod;
	else if (ffsz_eq(cs->arg->name, "log"))
		iface = &log_mod;
	else
		return FFCONF_EBADVAL;

	struct core_mod *m = mods_add(iface);

	const ffconf_arg *conf_args;
	void *conf_obj;
	m->iface->conf(&core, &conf_args, &conf_obj);

	if (0 != m->iface->sig(FDNS_SIG_INIT))
		return FFCONF_EBADVAL;
	m->initialized = 1;

	ffconf_scheme_addctx(cs, conf_args, conf_obj);
	return 0;
}

static const ffconf_arg root_args[] = {
	{ "log",	FFCONF_TOBJ, (ffsize)conf_mod },
	{ "dns",	FFCONF_TOBJ, (ffsize)conf_mod },
	{},
};

static int core_conf()
{
	int rc = -1;
	ffstr errmsg = {};
	ffvec confdata = {};
	ffstr fn = {};
	ffstr localfn = FFSTR_INITZ("fencedns.conf");
	fn = core.full_path(localfn);
	if (0 != fffile_readwhole(fn.ptr, &confdata, -1)) {
		fatal("file read: %S: %E", &fn, fferr_last());
		goto end;
	}
	ffstr cd = FFSTR_INITSTR(&confdata);
	int r = ffconf_parse_object(root_args, g, &cd, 0, &errmsg);
	if (r != 0) {
		fatal("config: %S: %S", &fn, &errmsg);
		goto end;
	}
	rc = 0;
end:
	ffstr_free(&fn);
	ffstr_free(&errmsg);
	ffvec_free(&confdata);
	return rc;
}
