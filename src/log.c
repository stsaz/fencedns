/** fencedns: log
2020, Simon Zolin */

#include <fencedns.h>
#include <FFOS/std.h>


struct log_conf {
	ffstr output;
};

struct log_ctx {
	fdns_core *core;
	struct log_conf conf;
};

static struct log_ctx *lx;

static int conf_log_level(ffconf_scheme *cs, void *obj, ffstr *val)
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
	int i = ffszarr_find(level_str, FF_COUNT(level_str), val->ptr, val->len);
	if (i < 0)
		return FFCONF_EBADVAL;
	lx->core->log_level = i;
	return 0;
}

static const ffconf_arg log_args[] = {
	{ "level",	FFCONF_TSTR, (ffsize)conf_log_level },
	{ "output",	FFCONF_TSTR, FF_OFF(struct log_conf, output) },
	{},
};

void fdns_log(int level, const char *fmt, va_list args)
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
	lx->core->time(1, &dt);
	ffstr_growfmt(&s, &cap, "%02u:%02u:%02u.%03u %s "
		, dt.hour, dt.minute, dt.second, dt.nanosecond/1000000
		, level_str[level - 1]);

	ffsize r = ffstr_growfmtv(&s, &cap, fmt, args);
	ffstr_growaddchar(&s, &cap, '\n');

	if (r != 0)
		ffstdout_write(s.ptr, s.len);
	ffstr_free(&s);
}

void log_conf(fdns_core *core, const ffconf_arg **conf_args, void **conf_obj)
{
	lx = ffmem_new(struct log_ctx);
	lx->core = core;
	lx->core->log_level = LOG_VERBOSE;
	*conf_args = log_args;
	*conf_obj = &lx->conf;
}

int log_sig(int sig)
{
	switch (sig) {
	case FDNS_SIG_DESTROY:
		ffstr_free(&lx->conf.output);
		ffmem_free(lx);  lx = NULL;
		break;
	}
	return 0;
}

struct fdns_mod log_mod = {
	"log",
	log_conf, log_sig,
};
