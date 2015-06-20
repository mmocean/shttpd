/*
 * Copyright (c) 2004-2005 Sergey Lyubka <valenok@gmail.com>
 * All rights reserved
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Sergey Lyubka wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 */

/*
 * Small and portable HTTP server, http://shttpd.sourceforge.net
 * $Id: shttpd.c,v 1.10 2007/06/01 17:59:32 drozd Exp $
 */

#include "defs.h"

time_t		current_time;	/* Current UTC time		*/
int		tz_offset;	/* Time zone offset from UTC	*/

//静态变量来着
static LL_HEAD(listeners);	/* List of listening sockets	*/

const struct vec known_http_methods[] = {
	{"GET",		3},
	{"POST",	4},
	{"PUT",		3},
	{"DELETE",	6},
	{"HEAD",	4},
	{NULL,		0}
};


/*
 *保存文件描述符,以及当前所属的核心环境变量
 *
 *
 * */

struct listener {
	struct llhead	link;
	struct shttpd_ctx *ctx;		/* Context that socket belongs	*/
	int		sock;		/* Listening socket		*/
	int		is_ssl;		/* Should be SSL-ed		*/
};

/*
 * This structure tells how HTTP headers must be parsed.
 * Used by parse_headers() function.
 */
#define	OFFSET(x)	offsetof(struct headers, x)
static const struct http_header http_headers[] = {
	{16, HDR_INT,	 OFFSET(cl),		"Content-Length: "	},
	{14, HDR_STRING, OFFSET(ct),		"Content-Type: "	},
	{12, HDR_STRING, OFFSET(useragent),	"User-Agent: "		},
	{19, HDR_DATE,	 OFFSET(ims),		"If-Modified-Since: "	},
	{15, HDR_STRING, OFFSET(auth),		"Authorization: "	},
	{9,  HDR_STRING, OFFSET(referer),	"Referer: "		},
	{8,  HDR_STRING, OFFSET(cookie),	"Cookie: "		},
	{10, HDR_STRING, OFFSET(location),	"Location: "		},
	{8,  HDR_INT,	 OFFSET(status),	"Status: "		},
	{7,  HDR_STRING, OFFSET(range),		"Range: "		},
	{12, HDR_STRING, OFFSET(connection),	"Connection: "		},
	{19, HDR_STRING, OFFSET(transenc),	"Transfer-Encoding: "	},
	{0,  HDR_INT,	 0,			NULL			}
};

struct shttpd_ctx *init_ctx(const char *config_file, int argc, char *argv[]);

int
url_decode(const char *src, int src_len, char *dst, int dst_len)
{
	int	i, j, a, b;
#define	HEXTOI(x)  (isdigit(x) ? x - '0' : x - 'W')

	for (i = j = 0; i < src_len && j < dst_len - 1; i++, j++)
		switch (src[i]) {
		case '%':
			if (isxdigit(((unsigned char *) src)[i + 1]) &&
			    isxdigit(((unsigned char *) src)[i + 2])) {
				a = tolower(((unsigned char *)src)[i + 1]);
				b = tolower(((unsigned char *)src)[i + 2]);
				dst[j] = (HEXTOI(a) << 4) | HEXTOI(b);
				i += 2;
			} else {
				dst[j] = '%';
			}
			break;
		case '+':
			dst[j] = ' ';
			break;
		default:
			dst[j] = src[i];
			break;
		}

	dst[j] = '\0';	/* Null-terminate the destination */

	return (j);
}

void
shttpd_add_mime_type(struct shttpd_ctx *ctx, const char *ext, const char *mime)
{
	struct mime_type_link	*e;
	const char		*error_msg = "shttpd_add_mime_type: no memory";

	if ((e = malloc(sizeof(*e))) == NULL) {
		elog(E_FATAL, 0, error_msg);
	} else if ((e->ext= my_strdup(ext)) == NULL) {
		elog(E_FATAL, 0, error_msg);
	} else if ((e->mime = my_strdup(mime)) == NULL) {
		elog(E_FATAL, 0, error_msg);
	} else {
		e->ext_len = strlen(ext);
		LL_TAIL(&ctx->mime_types, &e->link);
	}
}


static const char *
is_alias(struct shttpd_ctx *ctx, const char *uri,
		struct vec *a_uri, struct vec *a_path)
{
	const char	*p, *s = ctx->aliases;
	size_t		len;

	DBG(("is_alias: aliases [%s]", s == NULL ? "" : s));

	FOR_EACH_WORD_IN_LIST(s, len) {
		if ((p = memchr(s, '=', len)) != NULL &&
		    memcmp(uri, s, p - s) == 0) {
			a_uri->ptr = s;
			a_uri->len = p - s;
			a_path->ptr = ++p;
			a_path->len = (s + len) - p;
			return (s);
		}
	}

	return (NULL);
}

void
stop_stream(struct stream *stream)
{
	if (stream->io_class != NULL && stream->io_class->close != NULL)
		stream->io_class->close(stream);

	stream->io_class= NULL;
	stream->flags |= FLAG_CLOSED;
	//需要计算下right value = ?
	stream->flags &= ~(FLAG_R | FLAG_W | FLAG_ALWAYS_READY);

	DBG(("%d %s stopped. %lu of content data, %d now in a buffer",
	    stream->conn->rem.chan.sock, 
	    stream->io_class ? stream->io_class->name : "(null)",
	    (unsigned long) stream->io.total, io_data_len(&stream->io)));
}

/*
 * Setup listening socket on given port, return socket
 */
static int
open_listening_port(int port)
{
	int		sock, on = 1;
	struct usa	sa;

#ifdef _WIN32
	{WSADATA data;	WSAStartup(MAKEWORD(2,2), &data);}
#endif /* _WIN32 */

	/*
	 *设置sock属性 协议族 监听端口
	 *非阻塞 
	 *端口可重用:SO_REUSEADDR用于对TCP套接字处于TIME_WAIT状态下的socket,才可以重复绑定使用。
	 * */
	sa.len				= sizeof(sa.u.sin);
	sa.u.sin.sin_family		= AF_INET;
	sa.u.sin.sin_port		= htons((uint16_t) port);
	sa.u.sin.sin_addr.s_addr	= htonl(INADDR_ANY);


	/*
	 *步骤:创建sock,然后设置相关属性,然后绑定,然后再监听
	 *
	 * 然后就是等待连接,采用select查看状态,状态变了就accept.
	 * */
	if ((sock = socket(PF_INET, SOCK_STREAM, 6)) == -1)
		goto fail;
	if (set_non_blocking_mode(sock) != 0)
		goto fail;
	if (setsockopt(sock, SOL_SOCKET,
	    SO_REUSEADDR,(char *) &on, sizeof(on)) != 0)
		goto fail;
	if (bind(sock, &sa.u.sa, sa.len) < 0)
		goto fail;
	/*
	 *The backlog(128) argument defines the maximum length to which the queue of pending connections for sockfd  may grow.* */
	if (listen(sock, 128) != 0)
		goto fail;

#ifndef _WIN32
	/*
	 *close on exec, not on-fork, 意为如果对描述符设置了FD_CLOEXEC，使用execl执行的程序里，此描述符被关闭，不能再使用它，但是在使用fork调用的子进程中，此描述符并不关闭，仍可使用。
	 * */
	(void) fcntl(sock, F_SETFD, FD_CLOEXEC);
#endif /* !_WIN32 */

	return (sock);
fail:
	if (sock != -1)
		(void) closesocket(sock);
	elog(E_LOG, NULL, "open_listening_port(%d): %s", port, strerror(errno));
	return (-1);
}

/*
 * Check whether full request is buffered Return headers length, or 0
 */
//核心是过滤\r \n等尾串 返回真实的header长度
int
get_headers_len(const char *buf, size_t buflen)
{
	const char	*s, *e;
	int		len = 0;

	//s指向buf头部,e指向尾部
	//s指针向后移做遍历
	for (s = buf, e = s + buflen - 1; len == 0 && s < e; s++)
		/* Control characters are not allowed but >=128 is. */
		//isprint() checks for any printable character including space.
		if (!isprint(*(unsigned char *)s) && *s != '\r' && *s != '\n' && *(unsigned char *)s < 128)
			len = -1;
		else if (s[0] == '\n' && s[1] == '\n')//'\n'
			len = s - buf + 2;
		else if (s[0] == '\n' && &s[1] < e &&
		    s[1] == '\r' && s[2] == '\n')//'\r\n'
			len = s - buf + 3;

	return (len);
}

/*
 * Send error message back to a client.
 */
void
send_server_error(struct conn *c, int status, const char *reason)
{
#ifdef EMBEDDED
	struct llhead		*lp;
	struct error_handler	*e;

	LL_FOREACH(&c->ctx->error_handlers, lp) {
		e = LL_ENTRY(lp, struct error_handler, link);

		if (e->code == status) {
			if (c->loc.io_class != NULL &&
			    c->loc.io_class->close != NULL)
				c->loc.io_class->close(&c->loc);
			io_clear(&c->loc.io);
			setup_embedded_stream(c, e->callback, NULL);
			return;
		}
	}
#endif /* EMBEDDED */

	io_clear(&c->loc.io);
	c->loc.headers_len = c->loc.io.head = my_snprintf(c->loc.io.buf,
	    c->loc.io.size, "HTTP/1.1 %d %s\r\n\r\n%d %s",
	    status, reason, status, reason);
	c->status = status;
	stop_stream(&c->loc);
}

/*
 * Convert month to the month number. Return -1 on error, or month number
 */
static int
montoi(const char *s)
{
	static const char *ar[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	size_t	i;

	for (i = 0; i < sizeof(ar) / sizeof(ar[0]); i++)
		if (!strcmp(s, ar[i]))
			return (i);

	return (-1);
}

/*
 * Parse date-time string, and return the corresponding time_t value
 */
static time_t
date_to_epoch(const char *s)
{
	struct tm	tm, *tmp;
	char		mon[32];
	int		sec, min, hour, mday, month, year;

	(void) memset(&tm, 0, sizeof(tm));
	sec = min = hour = mday = month = year = 0;

	if (((sscanf(s, "%d/%3s/%d %d:%d:%d",
	    &mday, mon, &year, &hour, &min, &sec) == 6) ||
	    (sscanf(s, "%d %3s %d %d:%d:%d",
	    &mday, mon, &year, &hour, &min, &sec) == 6) ||
	    (sscanf(s, "%*3s, %d %3s %d %d:%d:%d",
	    &mday, mon, &year, &hour, &min, &sec) == 6) ||
	    (sscanf(s, "%d-%3s-%d %d:%d:%d",
	    &mday, mon, &year, &hour, &min, &sec) == 6)) &&
	    (month = montoi(mon)) != -1) {
		tm.tm_mday	= mday;
		tm.tm_mon	= month;
		tm.tm_year	= year;
		tm.tm_hour	= hour;
		tm.tm_min	= min;
		tm.tm_sec	= sec;
	}

	if (tm.tm_year > 1900)
		tm.tm_year -= 1900;
	else if (tm.tm_year < 70)
		tm.tm_year += 100;

	/* Set Daylight Saving Time field */
	tmp = localtime(&current_time);
	tm.tm_isdst = tmp->tm_isdst;

	return (mktime(&tm));
}

static void
remove_double_dots(char *s)
{
	char	*p = s;

	while (*s != '\0') {
		*p++ = *s++;
		if (s[-1] == '/')
			while (*s == '.' || *s == '/')
				s++;
	}
	*p = '\0';
}

void
parse_headers(const char *s, int len, struct headers *parsed)
{
	const struct http_header	*h;
	union variant			*v;
	const char			*p, *e = s + len;

	DBG(("parsing headers (len %d): [%.*s]", len, len, s));

	/* Loop through all headers in the request */
	while (s < e) {

		/* Find where this header ends */
		for (p = s; p < e && *p != '\n'; ) p++;

		/* Is this header known to us ? */
		//http_headers这是一个数组 存储着报文头的各种属性
		for (h = http_headers; h->len != 0; h++)
			if (e - s > h->len &&
			    !my_strncasecmp(s, h->name, h->len))
				break;

		/* If the header is known to us, store its value */
		if (h->len != 0) {

			/* Shift to where value starts */
			s += h->len;

			/* Find place to store the value */
			//变量v中数据最终是存到parsed变量中的
			v = (union variant *) ((char *) parsed + h->offset);

			/* Fetch header value into the connection structure */
			if (h->type == HDR_STRING) {
				v->v_vec.ptr = s;
				v->v_vec.len = p - s;
				if (p[-1] == '\r' && v->v_vec.len > 0)
					v->v_vec.len--;
			} else if (h->type == HDR_INT) {
				v->v_big_int = strtoul(s, NULL, 10);
			} else if (h->type == HDR_DATE) {
				v->v_time = date_to_epoch(s);
			}
		}

		s = p + 1;	/* Shift to the next header */
	}
}

/*
 * For given directory path, substitute it to valid index file.
 * Return 0 if index file has been found, -1 if not found
 */
static int
find_index_file(struct conn *c, char *path, size_t maxpath, struct stat *stp)
{
	char		buf[FILENAME_MAX];
	const char	*s = c->ctx->index_files;
	size_t		len;

	FOR_EACH_WORD_IN_LIST(s, len) {
		my_snprintf(buf, sizeof(buf), "%s%c%.*s",path, DIRSEP, len, s);
		if (my_stat(buf, stp) == 0) {
			my_strlcpy(path, buf, maxpath);
			c->mime_type = get_mime_type(c->ctx, s, len);
			return (0);
		}
	}

	return (-1);
}

/*
 * Try to open requested file, return 0 if OK, -1 if error.
 * If the file is given arguments using PATH_INFO mechanism,
 * initialize pathinfo pointer.
 */
static int
get_path_info(struct conn *c, char *path, struct stat *stp)
{
	char	*p, *e;

	if (my_stat(path, stp) == 0)
		return (0);

	p = path + strlen(path);
	e = path + strlen(c->ctx->document_root) + 2;
	
	/* Strip directory parts of the path one by one */
	for (; p > e; p--)
		if (*p == '/') {
			*p = '\0';
			if (!my_stat(path, stp) && !S_ISDIR(stp->st_mode)) {
				c->path_info = p + 1;
				return (0);
			} else {
				*p = '/';
			}
		}

	return (-1);
}


static void
decide_what_to_do(struct conn *c)
{
	char		path[URI_MAX], buf[1024];
	struct vec	alias_uri, alias_path;
	struct stat	st;
	int		rc;
#ifdef EMBEDDED
	struct registered_uri	*ruri;
#endif /* EMBEDDED */

	DBG(("decide_what_to_do: [%s]", c->uri));

	//?号后面的是携带的参数
	//比如采用get方式
	if ((c->query = strchr(c->uri, '?')) != NULL)
		*c->query++ = '\0';

	//source与dst都是c->uri,这一步具体是做什么的?
	url_decode(c->uri, strlen(c->uri), c->uri, strlen(c->uri) + 1);
	remove_double_dots(c->uri);

	//最大URI 8KB?
	if (strlen(c->uri) + strlen(c->ctx->document_root) >= sizeof(path)) {
		send_server_error(c, 400, "URI is too long");
		return;
	}

	//当前的root目录+文件名 = 绝对路径
	//可以改成直接使用文件名查找 - 自己的程序
	(void) my_snprintf(path, sizeof(path), "%s%s",
	    c->ctx->document_root, c->uri);

	/* User may use the aliases - check URI for mount point */
	//aliases选项可以读取root目录外的文件,假如设置了这种映射关系
	if (is_alias(c->ctx, c->uri, &alias_uri, &alias_path) != NULL) {
		(void) my_snprintf(path, sizeof(path), "%.*s%s",
		    alias_path.len, alias_path.ptr, c->uri + alias_uri.len);
		DBG(("using alias %.*s -> %.*s", alias_uri.len, alias_uri.ptr,
		    alias_path.len, alias_path.ptr));
	}

#if !defined(NO_AUTH)
	if (check_authorization(c, path) != 1) {
		//鉴权失败则发送失败的消息
		send_authorization_request(c);
	} else
#endif /* NO_AUTH */
#ifdef EMBEDDED
	if ((ruri = is_registered_uri(c->ctx, c->uri)) != NULL) {
		setup_embedded_stream(c, ruri->callback, ruri->callback_data);
	} else
#endif /* EMBEDDED */
	if (strstr(path, HTPASSWD)) {
		/* Do not allow to view passwords files */
		send_server_error(c, 403, "Forbidden");
	} else
#if !defined(NO_AUTH)
	if ((c->method == METHOD_PUT || c->method == METHOD_DELETE) &&
	    (c->ctx->put_auth_file == NULL || !is_authorized_for_put(c))) {
		send_authorization_request(c);
	} else
#endif /* NO_AUTH */
		//没有鉴权
		//还需要看put,post,get,delete等等方法的具体含义.
		/*
		 *GET用于检索已知的 Resource 表示。
		 POST用于创建新的、动态命名的 Resource。
		 PUT用于编辑已知 Resource。不用它来创建 Resource。
		 DELETE用于删除已知 Resource。
		 *
		 * */
	if (c->method == METHOD_PUT) {
		c->status = my_stat(path, &st) == 0 ? 200 : 201;

		if (c->ch.range.v_vec.len > 0) {
			send_server_error(c, 501, "PUT Range Not Implemented");
		} 
		else if ((rc = put_dir(path)) == 0) {
			send_server_error(c, 200, "OK");
		} 
		else if (rc == -1) {
			send_server_error(c, 500, "PUT Directory Error");
		} 
		else if (c->rem.content_len == 0) {
			send_server_error(c, 411, "Length Required");
		} 
		else if ((c->loc.chan.fd = my_open(path, O_WRONLY | O_BINARY |
		    O_CREAT | O_NONBLOCK | O_TRUNC, 0644)) == -1) {
			send_server_error(c, 500, "PUT Error");
		} 
		else {
			//调用写文件的方法
			DBG(("PUT file [%s]", c->uri));
			c->loc.io_class = &io_file;
			//采用标志位 - 可写
			c->loc.flags |= FLAG_W | FLAG_ALWAYS_READY ;
		}
	} 
	else if (c->method == METHOD_DELETE) {
		//一般来说 delete方法是默认禁止的 服务器应该是readonly的
		//返回的状态码貌似不是很对路,还需确认?
		DBG(("DELETE [%s]", c->uri));
		if (my_remove(path) == 0)
			send_server_error(c, 200, "OK");
		else
			send_server_error(c, 500, "DELETE Error");
	} 
	else if (get_path_info(c, path, &st) != 0) {
		//get当前文件,但找不到该文件
		send_server_error(c, 404, "Not Found");
	}
	else if (S_ISDIR(st.st_mode) && path[strlen(path) - 1] != '/') {
		//当前的path是个目录且没有子目录?
		(void) my_snprintf(buf, sizeof(buf),
			"Moved Permanently\r\nLocation: %s/", c->uri);
		send_server_error(c, 301, buf);
	}
	else if (S_ISDIR(st.st_mode) &&
	    find_index_file(c, path, sizeof(path) - 1, &st) == -1 &&
	    c->ctx->dirlist == 0) {
		send_server_error(c, 403, "Directory Listing Denied");
	}
	else if (S_ISDIR(st.st_mode) && c->ctx->dirlist) {
		if ((c->loc.chan.dir.path = my_strdup(path)) != NULL)
			get_dir(c);
		else
			send_server_error(c, 500, "GET Directory Error");
	} 
	else if (S_ISDIR(st.st_mode) && c->ctx->dirlist == 0) {
		send_server_error(c, 403, "Directory listing denied");

#if !defined(NO_CGI)
	} 
	else if (match_extension(path, c->ctx->cgi_extensions)) {
		//若不是post或者get方法 不行做CGI操作?
		if (c->method != METHOD_POST && c->method != METHOD_GET) {
			send_server_error(c, 501, "Bad method ");
		}
		//CGI需要研究一下
		else if ((run_cgi(c, path)) == -1) {
			send_server_error(c, 500, "Cannot exec CGI");
		} 
		else {
			do_cgi(c);
		}
#endif /* NO_CGI */

#if !defined(NO_SSI)
	} 
	else if (match_extension(path, c->ctx->ssi_extensions)) {
		if ((c->loc.chan.fd = my_open(path,
		    O_RDONLY | O_BINARY, 0644)) == -1) {
			send_server_error(c, 500, "SSI open error");
		} 
		else {
			do_ssi(c);
		}
#endif /* NO_CGI */

	} 
	else if (c->ch.ims.v_time && st.st_mtime <= c->ch.ims.v_time) {
		// 未修改 — 未按预期修改文档。  
		send_server_error(c, 304, "Not Modified");
	} 
	else if ((c->loc.chan.fd = my_open(path,
	    O_RDONLY | O_BINARY, 0644)) != -1) {
		get_file(c, &st);
	} 
	else {
		send_server_error(c, 500, "Internal Error");
	}
}

static int
set_request_method(struct conn *c)
{
	const struct vec	*v;

	assert(c->rem.io.head >= MIN_REQ_LEN);

	/* Set the request method */
	//由request的前几个字符来做判断,看方法是否实现
	//如get,post等
	for (v = known_http_methods; v->ptr != NULL; v++)
		if (!memcmp(c->rem.io.buf, v->ptr, v->len)) {
			c->method = v - known_http_methods;
			break;
		}

	return (v->ptr == NULL);
}



//解析http报文
//方法先判断,然后是版本判断,然后是资源符判断
static void
parse_http_request(struct conn *c)
{
	char	*s, *e, *p, *start;
	char	*end_number;
	int	uri_len, req_len;

	//rem.io.buf存储的是服务端从客户端读取的报文数据.
	s = c->rem.io.buf;
	req_len = c->rem.headers_len = get_headers_len(s, c->rem.io.head);

	//请求报文太大
	if (req_len == 0 && io_space_len(&c->rem.io) == 0)
		send_server_error(c, 400, "Request is too big");

	if (req_len == 0)
		return;
	else if (req_len < MIN_REQ_LEN)//最小长度
		send_server_error(c, 400, "Bad request");
	else if (set_request_method(c))//方法没有实现
		send_server_error(c, 501, "Method Not Implemented");
	else if ((c->request = my_strndup(s, req_len)) == NULL)//为什么要做一次拷贝呢?
		send_server_error(c, 500, "Cannot allocate request");

	//检查loc的文件标志位是否关闭
	if (c->loc.flags & FLAG_CLOSED)
		return;

	DBG(("Conn %d: parsing request: [%.*s]", c->rem.chan.sock, req_len, s));
	c->rem.flags |= FLAG_HEADERS_PARSED;

	/* Set headers pointer. Headers follow the request line */
	/*
	 * The  memchr()  function  scans  the first n bytes of the memory area pointed to by s for the character c.
	 *        The first byte to match c (interpreted as an unsigned character) stops the operation.
	 * void *memchr(const void *s, int c, size_t n);
	 * */
	//request的值是rem.io.buf中拷贝来的,然后在这之中查找第一个分行
	//也就是返回http请求报文的header部分
	c->headers = memchr(c->request, '\n', req_len);
	assert(c->headers != NULL);
	assert(c->headers < c->request + req_len);
	if (c->headers > c->request && c->headers[-1] == '\r')
		c->headers[-1] = '\0';
	*c->headers++ = '\0';

	//URI Uniform Resource Identifier
	//URL Uniform Resource Locator

	//请求行:方法 空格 资源 空格 版本 回车换行
	/*
	 * Now make a copy of the URI, because it will be URL-decoded,
	 * and we need a copy of unmodified URI for the access log.
	 * First, we skip the REQUEST_METHOD and shift to the URI.
	 */
	//跳过方法
	for (p = c->request, e = p + req_len; *p != ' ' && p < e; p++);
	while (p < e && *p == ' ') p++;

	//跳过URI
	/* Now remember where URI starts, and shift to the end of URI */
	for (start = p; p < e && !isspace((unsigned char)*p); ) p++;
	uri_len = p - start;//记录下URI的开始位置
	/* Skip space following the URI */
	while (p < e && *p == ' ') p++;

	//处理版本信息
	/* Now comes the HTTP-Version in the form HTTP/<major>.<minor> */
	if (strncmp(p, "HTTP/", 5) != 0) {
		send_server_error(c, 400, "Bad HTTP version");
		return;
	}
	p += 5;
	/* Parse the HTTP major version number */
	/*
	 *       The  strtoul()  function  converts  the  initial part of the string in nptr to an unsigned long int value
	 *              according to the given base, which must be between 2 and 36 inclusive, or be the special value 0.
	 * unsigned long int strtoul(const char *nptr, char **endptr, int base);
	 * 遇到数字或者正负号就开始转换,非数字以及结束符就停止转换
	 * */
	c->major_version = strtoul(p, &end_number, 10);
	if (end_number == p || *end_number != '.') {
		send_server_error(c, 400, "Bad HTTP major version");
		return;
	}
	p = end_number + 1;
	/* Parse the minor version number */
	c->minor_version = strtoul(p, &end_number, 10);
	if (end_number == p || *end_number != '\0') {
		send_server_error(c, 400, "Bad HTTP minor version");
		return;
	}
	/* Version must be <=1.1 */
	if (c->major_version > 1 ||
	    (c->major_version == 1 && c->minor_version > 1)) {
		send_server_error(c, 505, "HTTP version not supported");
		return;
	}

	if (uri_len <= 0) {
		send_server_error(c, 400, "Bad URI");
	} else if ((c->uri = malloc(uri_len + 1)) == NULL) {
		send_server_error(c, 500, "Cannot allocate URI");
	} else {
		//拷贝资源符号
		my_strlcpy(c->uri, (char *) start, uri_len + 1);
		//解析报文的其他属性
		parse_headers(c->headers,
		    (c->request + req_len) - c->headers, &c->ch);

		/* Remove the length of request from total, count only data */
		assert(c->rem.io.total >= (big_int_t) req_len);
		//这里为什么要从total中减去这个request的长度呢?
		c->rem.io.total -= req_len;

		c->rem.content_len = c->ch.cl.v_big_int;
		io_inc_tail(&c->rem.io, req_len);

		//根据解析的头文件进行下一步动作
		decide_what_to_do(c);
	}
}

void
shttpd_add_socket(struct shttpd_ctx *ctx, int sock)
{
	struct conn	*c;
	struct usa	sa;
	int		l = ctx->inetd_mode ? E_FATAL : E_LOG;
#if !defined(NO_SSL)
	SSL		*ssl = NULL;
#endif /* NO_SSL */

	sa.len = sizeof(sa.u.sin);
	//unix-like和win实现不同
	(void) set_non_blocking_mode(sock);

	//获取客户端IP信息
	// On success, zero is returned.  On error, -1 is returned, and errno is set appropriately.
	// getpeername()这里使用,不会进入到elog里面
	if (getpeername(sock, &sa.u.sa, &sa.len)) {
		elog(l, NULL, "add_socket: %s", strerror(errno));
#if !defined(NO_SSL)
	} else if (ctx->ssl_ctx && (ssl = SSL_new(ctx->ssl_ctx)) == NULL) {
		elog(l, NULL, "add_socket: SSL_new: %s", strerror(ERRNO));
		(void) closesocket(sock);
	} else if (ctx->ssl_ctx && SSL_set_fd(ssl, sock) == 0) {
		elog(l, NULL, "add_socket: SSL_set_fd: %s", strerror(ERRNO));
		(void) closesocket(sock);
		SSL_free(ssl);
#endif /* NO_SSL */
	} else if ((c = calloc(1, sizeof(*c) + 2 * ctx->io_buf_size)) == NULL) {
	/*默认io_buf_size= 16384/4096=4K bytes*/
#if !defined(NO_SSL)
		if (ssl)
			SSL_free(ssl);
#endif /* NO_SSL */
		(void) closesocket(sock);
		elog(l, NULL, "add_socket: calloc: %s", strerror(ERRNO));
	} else {
		//为何这里没有采用临界区的代码呢?
		ctx->nrequests++;//当期的sock请求数量自增1
		c->rem.conn = c->loc.conn = c;
		c->ctx		= ctx;/*指针指向*/
		c->sa		= sa;/*结构体复制*/
		c->birth_time	= current_time;
		c->expire_time	= current_time + EXPIRE_TIME;//连接失效时间为1小时:某个时候应该需要判断

		/*
		 * getsockname()  returns  the current address to which the socket sockfd is bound, in the buffer pointed to
		 *        by addr.  
		 *         int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
		 * */
		(void) getsockname(sock, &sa.u.sa, &sa.len);
		c->loc_port = sa.u.sin.sin_port;

		//各系统实现不一样
		//父进程关闭描述符,子进程还可以使用
		set_close_on_exec(sock);

		/*
		 *不明白为什么设置为空指针呢?
		 *io_class是一个结构体 保存着读,写,关闭文件流
		 * */
		c->loc.io_class	= NULL;

		//Remote stream 绑定了读写socket模式
		c->rem.io_class	= &io_socket;
		c->rem.chan.sock = sock;

		/* Set IO buffers */
		//注意这里:
		//指针c开辟的内存区大小为:sizeof(*c) + 2 * ctx->io_buf_size
		//所以loc.io.buf指向了全部的2 * ctx->io_buf_size,而rem.io.buf则指向了第二个ctx->io_buf_size
		//ctx->io_buf_size默认值是4KB
		//一页一般是4KB,但是sizeof(*c)应该没有4KB,这样应该还是要占两页,虽然大小是<8KB
		//可以采用getpagesize()测试一页的大小
		c->loc.io.buf	= (char *) (c + 1);
		c->rem.io.buf	= c->loc.io.buf + ctx->io_buf_size;
		//calloc开辟的空间,变量c的size初始值应该为0
		c->loc.io.size	= c->rem.io.size = ctx->io_buf_size;

#if !defined(NO_SSL)
		if (ssl) {
			c->rem.io_class	= &io_ssl;
			c->rem.chan.ssl.sock = sock;
			c->rem.chan.ssl.ssl = ssl;
			ssl_handshake(&c->rem);
		}
#endif /* NO_SSL */

		EnterCriticalSection(&ctx->mutex);
		//c->link虽然内部成员都是NULL值,但是它本身是有地址和空间的
		//这里相当于把临时alloc的c通过link加到了核心数据结构ctx的双向链表connections中了
		LL_TAIL(&ctx->connections, &c->link);
		ctx->nactive++;
		LeaveCriticalSection(&ctx->mutex);
	
		//The  inet_ntoa() function converts the Internet host address in, given in network byte order, to a string
		//in IPv4 dotted-decimal notation.  The string is returned in a statically allocated buffer,  which  subse-quent calls will overwrite.
		//inet_ntoa()不是线程安全的,返回一个指向静态区的指针,但是这个函数没有说是必须线程安全的
		//linux没发现带有_r suffix的可重入函数
		
		// The ntohs() function converts the unsigned short integer netshort from network byte order  to  host  byte order.
		DBG(("%s:%hu connected (socket %d)",
		    inet_ntoa(* (struct in_addr *) &sa.u.sin.sin_addr.s_addr),
		    ntohs(sa.u.sin.sin_port), sock));
	}
}

int
shttpd_active(struct shttpd_ctx *ctx)
{
	return (ctx->nactive);
}

/*
 * Setup a listening socket on given port. Return opened socket or -1
 */
int
shttpd_listen(struct shttpd_ctx *ctx, int port, int is_ssl)
{
	struct listener	*l;
	int		sock;

	if ((sock = open_listening_port(port)) == -1) {
		elog(E_FATAL, NULL, "cannot open port %d", port);
	} else if ((l = calloc(1, sizeof(*l))) == NULL) {
		//这里为何没有free呢?
		//calloc主要是申请后会将内存区初始化为0
		//closesocket是一个宏来着 是close的定义
		(void) closesocket(sock);
		elog(E_FATAL, NULL, "cannot allocate listener");
	} else if (is_ssl && ctx->ssl_ctx == NULL) {
		//没有给ssl_ctx分配空间,但是又指明采用ssl 报错
		(void) closesocket(sock);
		elog(E_FATAL, NULL, "cannot add SSL socket, "
		    "please specify certificate file");
	} else {
		l->is_ssl = is_ssl;
		l->sock	= sock;
		l->ctx	= ctx;
		//ctag有问题 这个listeners找不到定义
		LL_TAIL(&listeners, &l->link);
		DBG(("shttpd_listen: added socket %d", sock));
	}

	return (sock);
}

int
shttpd_accept(int lsn_sock, int milliseconds)
{
	struct timeval	tv;
	struct usa	sa;
	fd_set		read_set;
	int		sock = -1;
	
	tv.tv_sec	= milliseconds / 1000;
	tv.tv_usec	= milliseconds % 1000;
	sa.len		= sizeof(sa.u.sin);
	FD_ZERO(&read_set);
	FD_SET(lsn_sock, &read_set);
	
	if (select(lsn_sock + 1, &read_set, NULL, NULL, &tv) == 1)
		sock = accept(lsn_sock, &sa.u.sa, &sa.len);

	return (sock);
}

static void
read_stream(struct stream *stream)
{
	int	n, len;

	//应该是返回当前存储空间的可用大小
	len = io_space_len(&stream->io);
	assert(len > 0);

	/* Do not read more that needed */
	//stream->io.total + len是什么意思?
	if (stream->content_len > 0 &&
	    stream->io.total + len > stream->content_len)
		len = stream->content_len - stream->io.total;

	/* Read from underlying channel */
	//这里调用的是socket方法
	n = stream->nread_last = stream->io_class->read(stream,
	    io_space(&stream->io), len);

	if (n > 0)
		io_inc_head(&stream->io, n);//只有真实读取到了数据才操作
	else if (n == -1 && (ERRNO == EINTR || ERRNO == EWOULDBLOCK))
		//注意:这里有处理信号相关
		n = n;	/* Ignore EINTR and EAGAIN */
	else if (!(stream->flags & FLAG_DONT_CLOSE)) //FLAG_DONT_CLOSE=0x20 [00100000]
		//这个标志FLAG_DONT_CLOSE是谁来置的?
		//只要不是FLAG_DONT_CLOSE标志位,那么就关闭IO-stream
		//关闭发生在前两个条件都不满足的情况下
		stop_stream(stream);

	DBG(("read_stream (%d %s): read %d/%d/%lu bytes (errno %d)",
	    stream->conn->rem.chan.sock,
	    stream->io_class ? stream->io_class->name : "(null)",
	    n, len, (unsigned long) stream->io.total, ERRNO));

	/*
	 * Close the local stream if everything was read
	 * XXX We do not close the remote stream though! It may be
	 * a POST data completed transfer, we do not want the socket
	 * to be closed.
	 */
	if (stream->content_len > 0 && stream == &stream->conn->loc) {
		assert(stream->io.total <= stream->content_len);
		if (stream->io.total == stream->content_len)
			stop_stream(stream);
	}

	stream->conn->expire_time = current_time + EXPIRE_TIME;
}

static void
write_stream(struct stream *from, struct stream *to)
{
	int	n, len;

	len = io_data_len(&from->io);
	assert(len > 0);

	/* TODO: should be assert on CAN_WRITE flag */
	n = to->io_class->write(to, io_data(&from->io), len);
	to->conn->expire_time = current_time + EXPIRE_TIME;
	DBG(("write_stream (%d %s): written %d/%d bytes (errno %d)",
	    to->conn->rem.chan.sock,
	    to->io_class ? to->io_class->name : "(null)", n, len, ERRNO));

	if (n > 0)
		io_inc_tail(&from->io, n);
	//解决Hpux上的一个bug
	//EWOULDBLOCK与EAGAIN信号宏定义的差异
	else if (n == -1 && (ERRNO == EINTR || ERRNO == EWOULDBLOCK || ERRNO == EAGAIN))
		n = n;	/* Ignore EINTR and EAGAIN */
	else if (!(to->flags & FLAG_DONT_CLOSE))
		stop_stream(to);
}


static void
disconnect(struct conn *c)
{
	static const struct vec	ka = {"keep-alive", 10};
	int			dont_close;

	DBG(("Disconnecting %d (%.*s)", c->rem.chan.sock,
	    c->ch.connection.v_vec.len, c->ch.connection.v_vec.ptr));

#if !defined(_WIN32) || defined(NO_GUI)
	if (c->ctx->access_log != NULL)
#endif /* _WIN32 */
			log_access(c->ctx->access_log, c);

	/* In inetd mode, exit if request is finished. */
	//如果是daemon模式,直接退出,为何?
	if (c->ctx->inetd_mode)
		exit(0);

	//io_class初始值被设置的为NULL
	if (c->loc.io_class != NULL && c->loc.io_class->close != NULL)
		c->loc.io_class->close(&c->loc);

	/*
	 * Check the "Connection: " header before we free c->request
	 * If it its 'keep-alive', then do not close the connection
	 */
	//探测http的状态,如果是"keep-alive",那么就不要关闭这个连接
	//keep-alive模式:避免了建立或者重新建立连接
	dont_close =  c->ch.connection.v_vec.len >= ka.len &&
	    !my_strncasecmp(ka.ptr, c->ch.connection.v_vec.ptr, ka.len);

	//request存储的是前端发送的request报文
	//但是为什么要free掉呢?
	if (c->request)
		free(c->request);
	if (c->uri)
		free(c->uri);

	/* Handle Keep-Alive */
	dont_close = 0;
	if (dont_close) {
		c->loc.io_class = NULL;
		c->loc.flags = c->rem.flags = 0;
		c->query = c->request = c->uri = c->path_info = NULL;
		c->mime_type = NULL;
		(void) memset(&c->ch, 0, sizeof(c->ch));
		io_clear(&c->rem.io);
		io_clear(&c->loc.io);
		c->rem.io.total = c->loc.io.total = 0;
	} else {
		if (c->rem.io_class != NULL)
			c->rem.io_class->close(&c->rem);

		EnterCriticalSection(&c->ctx->mutex);
		LL_DEL(&c->link);
		c->ctx->nactive--;
		assert(c->ctx->nactive >= 0);
		LeaveCriticalSection(&c->ctx->mutex);

		free(c);
	}
}

static void
add_to_set(int fd, fd_set *set, int *max_fd)
{
	FD_SET(fd, set);
	if (fd > *max_fd)
		*max_fd = fd;
}

/*
 * One iteration of server loop. This is the core of the data exchange.
 */
//milliseconds 毫秒 
//做循环扫描 - 核心数据交互
void
shttpd_poll(struct shttpd_ctx *ctx, int milliseconds)
{
	struct llhead	*lp, *tmp;
	struct listener	*l;
	struct conn	*c;
	struct timeval	tv;			/* Timeout for select() */
	fd_set		read_set, write_set;//IO 可读 可写
	int		sock, max_fd = -1, msec = milliseconds;

	//Unified socket address 统一的地址 内部是个union
	struct usa	sa;

	current_time = time(0);
	FD_ZERO(&read_set);
	FD_ZERO(&write_set);

	/* Add listening sockets to the read set */
	//#define LL_FOREACH(H,N) for (N = (H)->next; N != (H); N = (N)->next)
	//循环对每一个监听的sock描述符做FD_SET
	LL_FOREACH(&listeners, lp) {
		l = LL_ENTRY(lp, struct listener, link);
		FD_SET(l->sock, &read_set);
		if (l->sock > max_fd)
			max_fd = l->sock;
		DBG(("FD_SET(%d) (listening)", l->sock));
	}

	/* Multiplex streams */
	/*这里没明白*/
	LL_FOREACH(&ctx->connections, lp) {
		c = LL_ENTRY(lp, struct conn, link);
		
		/* If there is a space in remote IO, check remote socket */
		if (io_space_len(&c->rem.io))
			add_to_set(c->rem.chan.fd, &read_set, &max_fd);

#if !defined(NO_CGI)
		/*
		 * If there is a space in local IO, and local endpoint is
		 * CGI, check local socket for read availability
		 */
		if (io_space_len(&c->loc.io) && (c->loc.flags & FLAG_R) &&
		    c->loc.io_class == &io_cgi)
			add_to_set(c->loc.chan.fd, &read_set, &max_fd);

		/*
		 * If there is some data read from remote socket, and
		 * local endpoint is CGI, check local for write availability
		 */
		if (io_data_len(&c->rem.io) && (c->loc.flags & FLAG_W) &&
		    c->loc.io_class == &io_cgi)
			add_to_set(c->loc.chan.fd, &write_set, &max_fd);
#endif /* NO_CGI */

		/*
		 * If there is some data read from local endpoint, check the
		 * remote socket for write availability
		 */
		if (io_data_len(&c->loc.io))
			add_to_set(c->rem.chan.fd, &write_set, &max_fd);

		if (io_space_len(&c->loc.io) && (c->loc.flags & FLAG_R) &&
		    (c->loc.flags & FLAG_ALWAYS_READY))
			msec = 0;
		
		if (io_data_len(&c->rem.io) && (c->loc.flags & FLAG_W) &&
		    (c->loc.flags & FLAG_ALWAYS_READY))
			msec = 0;
	}

	//需要每次都设置超时时间 否则第一次过后可能导致一直超时的问题
	tv.tv_sec = msec / 1000;
	tv.tv_usec = msec % 1000;

	/* Check IO readiness */
	//采用了select IO多路复用 就绪
	if (select(max_fd + 1, &read_set, &write_set, NULL, &tv) < 0) {
#ifdef _WIN32
		/*
		 * On windows, if read_set and write_set are empty,
		 * select() returns "Invalid parameter" error
		 * (at least on my Windows XP Pro). So in this case,
		 * we sleep here.
		 */
		Sleep(milliseconds);
#endif /* _WIN32 */
		DBG(("select: %d", ERRNO));
		return;
	}

	/* Check for incoming connections on listener sockets */
	//sleect返回大于0了 遍历查看各个端口连接
	LL_FOREACH(&listeners, lp) {
		l = LL_ENTRY(lp, struct listener, link);
		if (!FD_ISSET(l->sock, &read_set))
			continue;
		do {//集合准备就绪
			sa.len = sizeof(sa.u.sin);
			//这个sock是一个新的socket描述符
			if ((sock = accept(l->sock, &sa.u.sa, &sa.len)) != -1) {
#if defined(_WIN32)
				//win32难道没有连接数限制?
				shttpd_add_socket(ctx, sock);
#else
				if (sock < (int) FD_SETSIZE) {
					//设置了一些sock连接的参数,比如buf的大小,端口,生失效时间等等,然后把这个连接append到核心数据结构ctx的链表上
					shttpd_add_socket(ctx, sock);
				} else { /*超过FD_SETSIZE个连接就丢弃*/
					/*discarding not disarding*/
					elog(E_LOG, NULL,
					   "shttpd_poll: ctx %p: disarding "
					   "socket %d, too busy", ctx, sock);
					(void) closesocket(sock);
				}
#endif /* _WIN32 */
			}
		} while (sock != -1);
	}

	/* Process all connections */
	//所有的准备就绪的sock都初始化了之后,变量链表开始处理这些连接
	LL_FOREACH_SAFE(&ctx->connections, lp, tmp) {
		c = LL_ENTRY(lp, struct conn, link);

		/* Read from remote end if it is ready */
		//若读准备就绪且有空间可存储,就读取原始数据到buf
		if (FD_ISSET(c->rem.chan.fd, &read_set) &&
		    io_space_len(&c->rem.io))
			read_stream(&c->rem);

		/* If the request is not parsed yet, do so */
		//若0 == c->rem.flags则表示还没有解析
		//读完了数据就需要解析数据
		if (!(c->rem.flags & FLAG_HEADERS_PARSED))
			parse_http_request(c);

		DBG(("loc: %u [%.*s]", io_data_len(&c->loc.io),
		    io_data_len(&c->loc.io), io_data(&c->loc.io)));
		DBG(("rem: %u [%.*s]", io_data_len(&c->rem.io),
		    io_data_len(&c->rem.io), io_data(&c->rem.io)));

		/* Read from the local end if it is ready */
		if (io_space_len(&c->loc.io) &&
		    ((c->loc.flags & FLAG_ALWAYS_READY)
		    
#if !defined(NO_CGI)
		    ||(c->loc.io_class == &io_cgi &&
		     FD_ISSET(c->loc.chan.fd, &read_set))
#endif /* NO_CGI */
		    ))
			read_stream(&c->loc);

		//把处理的结果发送到客户端
		//调用socket的write函数
		if (io_data_len(&c->rem.io) > 0 && (c->loc.flags & FLAG_W) &&
		    c->loc.io_class != NULL && c->loc.io_class->write != NULL)
			write_stream(&c->rem, &c->loc);

		if (io_data_len(&c->loc.io) > 0 && c->rem.io_class != NULL)
			write_stream(&c->loc, &c->rem); 

		if (c->rem.nread_last > 0)
			c->ctx->in += c->rem.nread_last;
		if (c->loc.nread_last > 0)
			c->ctx->out += c->loc.nread_last;

		/* Check whether we should close this connection */
		//1.当期的时间已经大于了失效时间,那么就要关闭当前的连接
		//2.要看IO端口的状态:local段要等数据完全被读完知道超时才会关闭连接
		if ((current_time > c->expire_time) ||
		    (c->rem.flags & FLAG_CLOSED) ||
		    ((c->loc.flags & FLAG_CLOSED) && !io_data_len(&c->loc.io)))
			disconnect(c);
	}
}

/*
 * Deallocate shttpd object, free up the resources
 */
void
shttpd_fini(struct shttpd_ctx *ctx)
{
	struct llhead		*lp, *tmp;
	struct mime_type_link	*mtl;
	struct conn		*c;
	struct listener		*l;
	struct registered_uri	*ruri;

	/* Free configured mime types */
	LL_FOREACH_SAFE(&ctx->mime_types, lp, tmp) {
		mtl = LL_ENTRY(lp, struct mime_type_link, link);
		free(mtl->mime);
		free(mtl->ext);
		free(mtl);
	}

	/* Free all connections */
	LL_FOREACH_SAFE(&ctx->connections, lp, tmp) {
		c = LL_ENTRY(lp, struct conn, link);
		disconnect(c);
	}

	/* Free registered URIs (must be done after disconnect()) */
	LL_FOREACH_SAFE(&ctx->registered_uris, lp, tmp) {
		ruri = LL_ENTRY(lp, struct registered_uri, link);
		free((void *)ruri->uri);
		free(ruri);
	}

	/* Free listener sockets for this context */
	LL_FOREACH_SAFE(&listeners, lp, tmp) {
		l = LL_ENTRY(lp, struct listener, link);
		(void) closesocket(l->sock);
		LL_DEL(&l->link);
		free(l);
	}

#if !defined(NO_SSI)
	free_ssi_funcs(ctx);
#endif /* NO_SSI */

	if (ctx->access_log)		(void) fclose(ctx->access_log);
	if (ctx->error_log)		(void) fclose(ctx->error_log);
	if (ctx->put_auth_file)		free(ctx->put_auth_file);
	if (ctx->document_root)		free(ctx->document_root);
	if (ctx->index_files)		free(ctx->index_files);
	if (ctx->aliases)		free(ctx->aliases);
#if !defined(NO_CGI)
	if (ctx->cgi_vars)		free(ctx->cgi_vars);
	if (ctx->cgi_extensions)	free(ctx->cgi_extensions);
	if (ctx->cgi_interpreter)	free(ctx->cgi_interpreter);
#endif /* NO_CGI */
	if (ctx->auth_realm)		free(ctx->auth_realm);
	if (ctx->global_passwd_file)	free(ctx->global_passwd_file);
	if (ctx->uid)			free(ctx->uid);

	/* TODO: free SSL context */

	free(ctx);
}

void
open_listening_ports(struct shttpd_ctx *ctx)
{
	const char	*p = ctx->ports;
	int		len, is_ssl;

	//这是一个宏 字符串查找计算
	//DELIM_CHARS = ","
	//strcspn返回字符串开头连续N个不含有","字符数目
	// for (; s != NULL && (len = strcspn(s, DELIM_CHARS)) != 0; s += len + 1)
	// 若端口带s,如80s,则采用SSL方式
	// 可以同时监听多个端口
	FOR_EACH_WORD_IN_LIST(p, len) {
		is_ssl = p[len - 1] == 's' ? 1 : 0;
		if (shttpd_listen(ctx, atoi(p), is_ssl) == -1)
			elog(E_FATAL, NULL,
			    "Cannot open socket on port %d", atoi(p));
	}
}
