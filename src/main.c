/** fencedns: startup
2020, Simon Zolin */

#include <core.h>
#include <cmdline.h>
#include <FFOS/signal.h>
#include <FFOS/std.h>
#include <FFOS/ffos-extern.h>

static void onsig(struct ffsig_info *i)
{
	verbose("received signal %d", i->sig);
	switch (i->sig) {
	case SIGINT:
		core.cmd(FDNS_CORE_STOP);
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

int main(int argc, char **argv, char **env)
{
	int rc = 1;

	fflog("fencedns v%s", FDNS_VER_STR);

	if (NULL == core_create(argv))
		goto end;

	ffstr errmsg = {};
	int r = ffcmdarg_parse_object(args, g, (const char**)argv, argc, 0, &errmsg);
	if (r != 0) {
		if (r != -FFCMDARG_FIN)
			fatal("arguments: %S", &errmsg);
		goto end;
	}

	if (0 != core.cmd(FDNS_CORE_CONF))
		goto end;

	sigs_subscribe();

	if (0 != core.cmd(FDNS_CORE_START))
		goto end;
	core.cmd(FDNS_CORE_DESTROY);

	rc = 0;

end:
	ffstr_free(&errmsg);
	core_free();
	return rc;
}
