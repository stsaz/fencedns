/** fencedns: interfaces
2020, Simon Zolin */

#pragma once

#include <FF/data/conf2-scheme.h>
#include <FFOS/queue.h>
#include <FFOS/timerqueue.h>

#define FDNS_VER_STR  "0.2"

typedef void (*fdns_async_func)(void *param);
typedef fftimerqueue_node fdns_timer;

enum LOG_LEVEL {
	LOG_NONE,
	LOG_FATAL,
	LOG_ERROR,
	LOG_WARNING,
	LOG_INFO,
	LOG_VERBOSE,
	LOG_DEBUG,
};

enum FDNS_CORE {
	FDNS_CORE_CONF,
	FDNS_CORE_START,
	FDNS_CORE_STOP,
	FDNS_CORE_DESTROY,
};

enum FDNS_TIME {
	FDNS_TIME_UTC,
	FDNS_TIME_LOCAL,
	FDNS_TIME_MONO,
};

typedef struct fdns_core {
	ffkq kq;
	ffuint log_level;

	/** Execute command
	cmd: enum FDNS_CORE */
	int (*cmd)(int cmd, ...);

	/** Get full path name.
	Return a newly allocated string (NULL-terminated).  Free with ffstr_free(). */
	ffstr (*full_path)(ffstr name);

	/** Post an asynchronous task */
	int (*task)(fdns_async_func func, void *param);

	/** Enable/disable a timer
	interval_msec: >0:periodic;  <0:one-shot;  0:disable */
	int (*timer)(fdns_timer *t, int interval_msec, fdns_async_func func, void *param);

	/** Add a message to log.
	fmt: NOT standard printf-compatible! (see ffs_formatv)
	level: enum LOG_LEVEL */
	void (*log)(int level, const char *fmt, ...);
	void (*logv)(int level, const char *fmt, va_list args);

	/** Get the current time value
	flags: enum FDNS_TIME
	dt: optional */
	fftime (*time)(int flags, ffdatetime *dt);
} fdns_core;

enum FDNS_SIG {
	FDNS_SIG_INIT,
	FDNS_SIG_START,
	FDNS_SIG_STOP,
	FDNS_SIG_RECONFIG,
	FDNS_SIG_CLEAR,
	FDNS_SIG_DESTROY,
};

struct fdns_mod {
	const char *name;

	void (*conf)(fdns_core *core, const ffconf_arg **conf_args, void **conf_obj);

	/** Send signal to a module
	sig: enum FDNS_SIG */
	int (*sig)(int sig);
};

extern struct fdns_mod dns_mod;
extern struct fdns_mod log_mod;
void fdns_log(int level, const char *fmt, va_list args);

typedef void (*ffkevent_func)(void *param);

typedef struct ffkevent2 {
	ffkevent_func func;
	void *param;
} ffkevent2;
