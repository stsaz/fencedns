/** fencedns: interfaces
2020, Simon Zolin */

#pragma once

#include <FF/data/conf2-scheme.h>
#include <FFOS/queue.h>
#include <FFOS/timerqueue.h>

#define FDNS_VER_STR  "0.1"

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

typedef struct fdns_core {
	ffkq kq;
	ffuint log_level;

	int (*cmd)(int cmd);

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

	/** Get the current time value
	flags: 0:UTC; 1:local
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
