/** fencedns: core
2020, Simon Zolin */

#include <fencedns.h>
#include <FFOS/time.h>
#include <FFOS/perf.h>
#include <FFOS/path.h>
#include <FFOS/process.h>

static fdns_core core;
static struct core_mod* mods_add(struct fdns_mod *iface);

#define fatal(...)  core.log(LOG_FATAL, __VA_ARGS__)
#define error(...)  core.log(LOG_ERROR, __VA_ARGS__)
#define warning(...)  core.log(LOG_WARNING, __VA_ARGS__)
#define info(...)  core.log(LOG_INFO, __VA_ARGS__)
#define verbose(...)  core.log(LOG_VERBOSE, __VA_ARGS__)
#define debug(...)  core.log(LOG_DEBUG, __VA_ARGS__)

struct core_mod {
	struct fdns_mod *iface;
	int initialized;
};

struct core_data {
	fftime_zone tz;
	ffstr bin_fullpath;
	ffstr root_dir;
	ffvec mods; // struct core_mod[]
};
struct core_data *g;

#include <conf.h>

static struct core_mod* mods_add(struct fdns_mod *iface)
{
	struct core_mod *m = ffvec_pushT(&g->mods, struct core_mod);
	debug("core: initializing module: %s", iface->name);
	m->iface = iface;
	return m;
}

static int mods_sig(int sig)
{
	struct core_mod *m;
	FFSLICE_WALK_T(&g->mods, m, struct core_mod) {
		debug("core: signal to module %s: %d", m->iface->name, sig);
		int r = m->iface->sig(sig);
		if (r != 0) {
			error("core: module %s returned %d on signal %d", m->iface->name, r, sig);
			return r;
		}
	}
	return 0;
}

struct core_data* core_create(char **argv)
{
	g = ffmem_new(struct core_data);
	fftime_local(&g->tz);

	ffstr_alloc(&g->bin_fullpath, 4096);
	ffps_filename(g->bin_fullpath.ptr, 4096, argv[0]);
	g->bin_fullpath.len = ffsz_len(g->bin_fullpath.ptr);
	if (ffstr_rsplitby(&g->bin_fullpath, '/', &g->root_dir, NULL) >= 0)
		g->root_dir.len++;
	else // no slash in full path
		ffstr_setz(&g->root_dir, "/");

	return g;
}

void core_free()
{
	ffstr_free(&g->bin_fullpath);
	ffvec_free(&g->mods);
	ffmem_free(g);  g = NULL;
}

static void core_destroy()
{
	struct core_mod *m;
	FFSLICE_RWALK_T(&g->mods, m, struct core_mod) {
		if (!m->initialized)
			continue;
		debug("core: signal to module %s: %d", m->iface->name, FDNS_SIG_DESTROY);
		m->iface->sig(FDNS_SIG_DESTROY);
		m->initialized = 0;
	}
}

static int core_cmd(int cmd, ...)
{
	switch ((enum FDNS_CORE)cmd) {
	case FDNS_CORE_CONF:
		return core_conf();

	case FDNS_CORE_START:
		return mods_sig(FDNS_SIG_START);

	case FDNS_CORE_STOP:
		return mods_sig(FDNS_SIG_STOP);

	case FDNS_CORE_DESTROY:
		core_destroy();
		return 0;
	}
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

static void default_logger(int level, const char *fmt, va_list args)
{
	if (level >= LOG_VERBOSE)
		return;

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

	ffsize r = ffstr_growfmtv(&s, &cap, fmt, args);
	ffstr_growaddchar(&s, &cap, '\n');

	if (r != 0)
		ffstdout_write(s.ptr, s.len);
	ffstr_free(&s);
}

static void core_log(int level, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	core.logv(level, fmt, args);
	va_end(args);
}

static fftime core_time(int flags, ffdatetime *dt)
{
	fftime now;

	switch (flags) {
	case 0:
		fftime_now(&now);
		break;
	case 1:
		fftime_now(&now);
		now.sec += g->tz.real_offset;
		break;
	case 2:
		return fftime_monotonic();
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
	.log = core_log,
	.logv = default_logger,
	core_time,
};
