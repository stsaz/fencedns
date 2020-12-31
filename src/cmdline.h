/** fencedns: command-line parser
2020, Simon Zolin */

#include <fencedns.h>
#include <FF/data/cmdarg-scheme.h>

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

static int arg_install(ffcmdarg_scheme *as, void *obj)
{
	const char *fn = "/usr/lib/systemd/system/fencedns.service";
	int r = svc_install(fn, g->bin_fullpath);
	return (r == 0) ? FFCMDARG_FIN : FFCMDARG_ERROR;
}

static int arg_debug(ffcmdarg_scheme *as, void *obj)
{
	core.log_level = LOG_DEBUG;
	return 0;
}

static int arg_help(ffcmdarg_scheme *as, void *obj)
{
	fflog(
"\
--install          Install service (systemd)\n\
-D, --debug        Set debug log level\n\
-h, --help         Show help info\
");
	return FFCMDARG_FIN;
}

static const ffcmdarg_arg args[] = {
	{ 0, "install", FFCMDARG_TSWITCH, (ffsize)arg_install },
	{ 'D', "debug", FFCMDARG_TSWITCH, (ffsize)arg_debug },
	{ 'h', "help", FFCMDARG_TSWITCH, (ffsize)arg_help },
	{},
};
