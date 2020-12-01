/** fencedns: startup
2020, Simon Zolin */

#include <fencedns.h>
#include <FF/data/cmdarg-scheme.h>
#include <FFOS/signal.h>
#include <FFOS/path.h>
#include <FFOS/std.h>
#include <FFOS/process.h>
#include <FFOS/ffos-extern.h>

struct core_data {
	fftime_zone tz;
	ffstr bin_fullpath;
	ffstr root_dir;
};
struct core_data *g;

static int core_cmd(int cmd)
{
	return -1;
}

static ffstr core_full_path(ffstr name)
{
	ffstr s = {};

	if (ffpath_abs(name.ptr, name.len)) {
		s.ptr = ffsz_dupn(name.ptr, name.len);
		s.len = name.len;

	} else {
		ffsize cap = 0;
		ffstr_growfmt(&s, &cap, "%S%S%Z"
			, &g->root_dir, &name);
		s.len--;
	}
	return s;
}

static int core_task(fdns_async_func func, void *param)
{
	return -1;
}

static int core_timer(fdns_timer *t, int interval_msec, fdns_async_func func, void *param)
{
	return -1;
}

static void def_log(int level, const char *fmt, ...)
{
	ffstr s = {};
	ffsize cap = 0;

	static const char level_str[][6] = {
		"FATAL",
		"ERROR",
		"WARN ",
		"INFO ",
		"VERB ",
		"DEBUG",
	};
	ffstr_growfmt(&s, &cap, "%s "
		, level_str[level - 1]);

	va_list args;
	va_start(args, fmt);
	ffsize r = ffstr_growfmtv(&s, &cap, fmt, args);
	va_end(args);
	ffstr_growaddchar(&s, &cap, '\n');

	if (r != 0)
		ffstdout_write(s.ptr, s.len);
	ffstr_free(&s);
}

static void core_log(int level, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fdns_log(level, fmt, args);
	va_end(args);
}

static fftime core_time(int flags, ffdatetime *dt)
{
	fftime now;
	fftime_now(&now);

	switch (flags) {
	case 0:
		break;
	case 1:
		now.sec += g->tz.real_offset;
		break;
	}

	if (dt != NULL) {
		fftime_split1(dt, &now);
	}

	return now;
}

static fdns_core core = {
	0, 0,
	core_cmd,
	core_full_path,
	core_task,
	core_timer,
	core_log,
	core_time,
};


#define fatal(...)  core.log(LOG_FATAL, __VA_ARGS__)
#define error(...)  core.log(LOG_ERROR, __VA_ARGS__)
#define warning(...)  core.log(LOG_WARNING, __VA_ARGS__)
#define info(...)  core.log(LOG_INFO, __VA_ARGS__)
#define verbose(...)  core.log(LOG_VERBOSE, __VA_ARGS__)
#define debug(...)  core.log(LOG_DEBUG, __VA_ARGS__)

static int svc_install(const char *fn, ffstr bin_path)
{
	const char *template_systemd =
"[Unit]\n\
Description=Fast anti-ad DNS server\n\
DefaultDependencies=false\n\
After=network.target\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart=%S\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n";

	ffstr data = {};
	ffsize cap = 0;
	ffstr_growfmt(&data, &cap, template_systemd, &bin_path);
	int r = fffile_writewhole(fn, data.ptr, data.len, 0);
	if (r != 0)
		error("file write: %s: %E", fn, fferr_last());
	else
		info("installed service: %s", fn);
	ffstr_free(&data);
	return r;
}

static void onsig(struct ffsig_info *i)
{
	verbose("received signal %d", i->sig);
	switch (i->sig) {
	case SIGINT:
		dns_mod.sig(FDNS_SIG_STOP);
		break;

	case SIGHUP:
		dns_mod.sig(FDNS_SIG_RECONFIG);
		break;

	case SIGUSR1:
		dns_mod.sig(FDNS_SIG_CLEAR);
		break;
	}
}

static void sigs_subscribe()
{
	static ffuint sigs[] = { SIGINT, SIGHUP, SIGUSR1 };
	if (0 != ffsig_subscribe(onsig, sigs, FF_COUNT(sigs))){
		error("ffsig_subscribe: %E", fferr_last());
	}
}

static int arg_install(ffcmdarg_scheme *as, void *obj)
{
	const char *fn = "/usr/lib/systemd/system/fencedns.service";
	int r = svc_install(fn, g->bin_fullpath);
	return (r == 0) ? FFCMDARG_FIN : FFCMDARG_ERROR;
}

static int arg_help(ffcmdarg_scheme *as, void *obj)
{
	fflog(
"--install   Install service (systemd)\n\
-h  --help  Show help info");
	return FFCMDARG_FIN;
}

static const ffcmdarg_arg args[] = {
	{ 0, "install", FFCMDARG_TSWITCH, (ffsize)arg_install },
	{ 'h', "help", FFCMDARG_TSWITCH, (ffsize)arg_help },
	{},
};

int conf_log(ffconf_scheme *cs, void *obj)
{
	const ffconf_arg *conf_args;
	void *conf_obj;
	log_mod.conf(&core, &conf_args, &conf_obj);
	core.log = core_log;
	ffconf_scheme_addctx(cs, conf_args, conf_obj);
	return 0;
}

static int conf_dns(ffconf_scheme *cs, void *obj)
{
	debug("core: initializing module: %s", dns_mod.name);

	const ffconf_arg *conf_args;
	void *conf_obj;
	dns_mod.conf(&core, &conf_args, &conf_obj);

	// if (0 != dns_mod.sig(FDNS_SIG_INIT))
	// 	goto end;

	ffconf_scheme_addctx(cs, conf_args, conf_obj);
	return 0;
}

static const ffconf_arg root_args[] = {
	{ "log",	FFCONF_TOBJ, (ffsize)conf_log },
	{ "dns",	FFCONF_TOBJ, (ffsize)conf_dns },
	{},
};


int main(int argc, char **argv, char **env)
{
	int rc = 1;
	ffstr fn = {};
	ffvec confdata = {};
	core.log = def_log;

	fflog("fencedns v%s", FDNS_VER_STR);

	g = ffmem_new(struct core_data);
	fftime_local(&g->tz);
	ffstr_alloc(&g->bin_fullpath, 4096);
	ffps_filename(g->bin_fullpath.ptr, 4096, argv[0]);
	g->bin_fullpath.len = ffsz_len(g->bin_fullpath.ptr);

	if (ffstr_rsplitby(&g->bin_fullpath, '/', &g->root_dir, NULL) >= 0)
		g->root_dir.len++;
	else // no slash in full path
		ffstr_setz(&g->root_dir, "/");

	ffstr errmsg = {};
	int r = ffcmdarg_parse_object(args, g, (const char**)argv, argc, 0, &errmsg);
	if (r != 0) {
		if (r != -FFCMDARG_FIN)
			fatal("arguments: %S", &errmsg);
		goto end;
	}

	ffstr localfn = FFSTR_INITZ("fencedns.conf");
	fn = core.full_path(localfn);
	if (0 != fffile_readwhole(fn.ptr, &confdata, -1)) {
		fatal("file read: %S: %E", &fn, fferr_last());
		goto end;
	}
	ffstr cd = FFSTR_INITSTR(&confdata);
	r = ffconf_parse_object(root_args, g, &cd, 0, &errmsg);
	if (r != 0) {
		fatal("config: %S: %S", &fn, &errmsg);
		goto end;
	}

	sigs_subscribe();

	debug("core: starting module: %s", dns_mod.name);
	if (0 != dns_mod.sig(FDNS_SIG_START))
		goto end;
	if (0 != dns_mod.sig(FDNS_SIG_STOP))
		goto end;
	if (0 != dns_mod.sig(FDNS_SIG_DESTROY))
		goto end;
	debug("core: closed module: %s", dns_mod.name);

	if (0 != log_mod.sig(FDNS_SIG_DESTROY))
		goto end;

	rc = 0;

end:
	ffstr_free(&errmsg);
	ffvec_free(&confdata);
	ffstr_free(&fn);
	ffstr_free(&g->bin_fullpath);
	ffmem_free(g);
	return rc;
}
