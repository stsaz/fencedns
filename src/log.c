/** fencedns: log
2020, Simon Zolin */

#include <fencedns.h>
#include <FFOS/std.h>
#include <FFOS/process.h>

#define error(...)  lx->core->log(LOG_ERROR, __VA_ARGS__)

struct log_conf {
	ffvec output; // char*[]
};

struct log_out {
	const char *name;
	fffd f;
};

struct log_ctx {
	fdns_core *core;
	ffvec outputs; // struct log_out[]
	int pid;
	struct log_conf conf;
};

static struct log_ctx *lx;

static int conf_level(ffconf_scheme *cs, void *obj, ffstr *val)
{
	static const char *const level_str[] = {
		"none",
		"fatal",
		"error",
		"warning",
		"info",
		"verbose",
		"debug",
	};
	ffuint i = ffszarr_find(level_str, FF_COUNT(level_str), val->ptr, val->len);
	if ((int)i < 0)
		return FFCONF_EBADVAL;
	if (lx->core->log_level != LOG_DEBUG) // keep value from '-D' cmd line switch
		lx->core->log_level = i;
	return 0;
}

static int conf_output(ffconf_scheme *cs, void *obj, ffstr *val)
{
	char **s = ffvec_pushT(&lx->conf.output, char*);
	if (ffstr_eqz(val, "stdout"))
		*s = ffsz_dup("stdout");
	else
		*s = lx->core->full_path(*val).ptr;
	return 0;
}

static const ffconf_arg log_args[] = {
	{ "level",	FFCONF_TSTR, (ffsize)conf_level },
	{ "output",	FFCONF_TSTR, (ffsize)conf_output },
	{},
};

// TIME #PID LEVEL MSG
void log_msg(int level, const char *fmt, va_list args)
{
	if (level == 0 || (ffuint)level > lx->core->log_level)
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
	ffdatetime dt;
	lx->core->time(FDNS_TIME_LOCAL, &dt);
	ffstr_growfmt(&s, &cap, "%02u:%02u:%02u.%03u #%d %s "
		, dt.hour, dt.minute, dt.second, dt.nanosecond/1000000
		, lx->pid
		, level_str[level - 1]);

	ffsize r = ffstr_growfmtv(&s, &cap, fmt, args);
	ffstr_growaddchar(&s, &cap, '\n');

	if (r != 0) {
		struct log_out *o;
		FFSLICE_WALK(&lx->outputs, o) {
			if (ffsz_eq(o->name, "stdout"))
				ffstdout_write(s.ptr, s.len);
			else
				fffile_write(o->f, s.ptr, s.len);
		}
	}
	ffstr_free(&s);
}

void log_conf(fdns_core *core, const ffconf_arg **conf_args, void **conf_obj)
{
	lx = ffmem_new(struct log_ctx);
	lx->core = core;
	if (lx->core->log_level != LOG_DEBUG) // keep value from '-D' cmd line switch
		lx->core->log_level = LOG_VERBOSE;
	*conf_args = log_args;
	*conf_obj = &lx->conf;
}

int log_open()
{
	const char **fn;
	FFSLICE_WALK(&lx->conf.output, fn) {

		struct log_out *o = ffvec_pushT(&lx->outputs, struct log_out);
		o->name = *fn;
		o->f = FFFILE_NULL;

		if (ffsz_eq(*fn, "stdout")) {
			continue;
		}

		o->f = fffile_open(o->name, FFFILE_CREATE | FFFILE_WRITEONLY | FFFILE_APPEND);
		if (o->f == FFFILE_NULL) {
			error("log: file open: %s: %E", o->name, fferr_last());
		}
	}

	lx->pid = ffps_curid();
	return 0;
}

void log_free()
{
	struct log_out *o;
	FFSLICE_WALK(&lx->outputs, o) {
		fffile_close(o->f);
	}
	ffvec_free(&lx->outputs);

	char **fn;
	FFSLICE_WALK(&lx->conf.output, fn) {
		ffmem_free(*fn);
	}
	ffvec_free(&lx->conf.output);
	ffmem_free(lx);  lx = NULL;
}

int log_sig(int sig)
{
	switch (sig) {
	case FDNS_SIG_START:
		if (0 != log_open())
			return -1;
		lx->core->logv = log_msg;
		break;

	case FDNS_SIG_DESTROY:
		// lx->core->logv = ;
		log_free();
		break;
	}
	return 0;
}

struct fdns_mod log_mod = {
	"log",
	log_conf, log_sig,
};
