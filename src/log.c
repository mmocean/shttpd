/*
 * Copyright (c) 2004-2005 Sergey Lyubka <valenok@gmail.com>
 * All rights reserved
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Sergey Lyubka wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 */

#include "defs.h"

/*
 * Log function
 */

//若是FATAL错误 则会直接exit
//若没有连接就写NULL,否则写到该连接的erro_log中
void
elog(int flags, struct conn *c, const char *fmt, ...)
{
	char	date[64], buf[URI_MAX];
	int	len;
	FILE	*fp = c == NULL ? NULL : c->ctx->error_log;
	va_list	ap;

	/* Print to stderr */
	if (c == NULL || c->ctx->inetd_mode == 0) {
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		(void) fputc('\n', stderr);
		va_end(ap);
	}

	strftime(date, sizeof(date), "%a %b %d %H:%M:%S %Y",
	    localtime(&current_time));

	len = my_snprintf(buf, sizeof(buf),
	    "[%s] [error] [client %s] \"%s\" ",
	    date, c ? inet_ntoa(c->sa.u.sin.sin_addr) : "-",
	    c && c->request ? c->request : "-");

	va_start(ap, fmt);
	(void) vsnprintf(buf + len, sizeof(buf) - len, fmt, ap);
	va_end(ap);

	buf[sizeof(buf) - 1] = '\0';

	if (fp != NULL && (flags & (E_FATAL | E_LOG))) {
		(void) fprintf(fp, "%s\n", buf);
		(void) fflush(fp);
	}

#if defined(_WIN32) && !defined(NO_GUI)
	{
		extern HWND	hLog;

		if (hLog != NULL)
			SendMessage(hLog, WM_APP, 0, (LPARAM) buf);
	}
#endif /* _WIN32 */

	if (flags & E_FATAL)
		exit(EXIT_FAILURE);
}

void
log_access(FILE *fp, const struct conn *c)
{
	static const struct vec	dash = {"-", 1};

	const struct vec	*user = &c->ch.user.v_vec;
	const struct vec	*referer = &c->ch.referer.v_vec;
	const struct vec	*user_agent = &c->ch.useragent.v_vec;
	char			date[64], buf[URI_MAX], *q1 = "\"", *q2 = "\"";

	if (user->len == 0)
		user = &dash;

	if (referer->len == 0) {
		referer = &dash;
		q1 = "";
	}

	if (user_agent->len == 0) {
		user_agent = &dash;
		q2 = "";
	}

	(void) strftime(date, sizeof(date), "%d/%b/%Y:%H:%M:%S",
			localtime(&current_time));

	(void) my_snprintf(buf, sizeof(buf),
	    "%s - %.*s [%s %+05d] \"%s\" %d %lu %s%.*s%s %s%.*s%s",
	    inet_ntoa(c->sa.u.sin.sin_addr), user->len, user->ptr,
	    date, tz_offset, c->request ? c->request : "-",
	    c->status, (unsigned long) c->loc.io.total,
	    q1, referer->len, referer->ptr, q1,
	    q2, user_agent->len, user_agent->ptr, q2);

	if (fp != NULL) {
		(void) fprintf(fp, "%s\n", buf);
		(void) fflush(fp);
	}

#if defined(_WIN32) && !defined(NO_GUI)
	{
		extern HWND	hLog;

		if (hLog != NULL)
			SendMessage(hLog, WM_APP, 0, (LPARAM) buf);
	}
#endif /* _WIN32 */
}
