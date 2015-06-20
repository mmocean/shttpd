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

static int
read_socket(struct stream *stream, void *buf, size_t len)
{
	assert(stream->chan.sock != -1);
	//直接采用recv方法从sock描述符中读取len个数据放入buf中
	// The flags argument to a recv() call is formed by OR’ing one or more of the following values:
	// 这个可以关注下这个函数的使用
	// 错误怎么处理的?比如信号中断怎么处理?
	return (recv(stream->chan.sock, buf, len, 0));
}

static int
write_socket(struct stream *stream, const void *buf, size_t len)
{
	assert(stream->chan.sock != -1);
	return (send(stream->chan.sock, buf, len, 0));
}

static void
close_socket(struct stream *stream)
{
	assert(stream->chan.sock != -1);
	(void) closesocket(stream->chan.sock);
}

const struct io_class	io_socket =  {
	"socket",
	read_socket,
	write_socket,
	close_socket
};
