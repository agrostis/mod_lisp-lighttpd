/* ========================================================================

  This is a branch of mod_lisp for the lighttpd server.  The original mod_lisp
  (for Apache) has been written by Marc Battyani and based on the example module
  from the Apache distribution, and various other modules.  mod_lisp_lighttpd is
  based on modules provided with the lighttpd source, primarily mod_proxy.

  It is distributed under a FreeBSD style license (if you want another license
  contact me at boris.smilga (at) gmail (dot) com).  Various portions of code
  are due to the copyright holders below.  The Apache licence has been retained
  for legacy reasons, although ostensibly no Apache code is left in the source.

  ========================================================================= */

/* ========================================================================
 * Copyright (c) 2000-2004 Marc Battyani.
 * Copyright (c) 2004 Jan Kneschke, incremental.
 * Copyright (c) 2006 Boris Smilga.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT
 * SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS TO EITHER THE APACHE OR THE LIGHTTPD
 * BRANCH BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ======================================================================== */

/* ========================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 * display the following acknowledgment: "This product includes software
 * developed by the Apache Group for use in the Apache HTTP server project
 * (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to endorse
 * or promote products derived from this software without prior written
 * permission. For written permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache" nor may
 * "Apache" appear in their names without prior written permission of the Apache
 * Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 * acknowledgment: "This product includes software developed by the Apache Group
 * for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY EXPRESSED OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE APACHE GROUP OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ========================================================================
 *
 * This software consists of voluntary contributions made by many individuals on
 * behalf of the Apache Group and was originally based on public domain software
 * written at the National Center for Supercomputing Applications, University of
 * Illinois, Urbana-Champaign. For more information on the Apache Group and the
 * Apache HTTP server project, please see <http://www.apache.org/>.
 * ======================================================================== */

/* == Change log ==========================================================

  Version L.0.2
  Changed some int-type variables to unsigned short so as to remove reliance
  on my private changes to base.h and config-glue.c (see ticket 627 and the
  ensuing discussion on trac.lighttpd.net).

  Version L.0.1

  This is a branch of mod_lisp for Apache v. 2.43, adapted for lighttpd.  This
  and all subsequent versions shall have ``L.'' prepended to them, so as to
  distinguish them from the main mod_lisp-for-Apache trunk.  The maintainer of
  this program should strive to keep it synched with the trunk.

  === Change log for the Apache mod_lisp ==================================

  Version 2.43
  fixed possible memory leak when the connection to the Lisp process fails (Alain Picard)
  Set r->mtime directly (Edi Weitz)
  
  Version 2.42
  Added "Lisp-Content-Length" header
  (send after "Content-Length" header to overwrite its value)

  Version 2.41
  Case insensitive version of the set-cookie

  Version 2.40
  Allow more than one Set-Cookie
  (it was added in 2.2 but was wrongly removed in 2.35)

  Version 2.39
  Case insensitive parsing of the Lisp header names
  (for compatibility with mod_lisp2)

  Version 2.38
  New "server-baseversion" and "modlisp-version" headers
  (Edi Weitz)

  Version 2.37
  Create new socket (instead of reusing) if IP/port combo has changed
  (Edi Weitz)

  Version 2.36
  Close Lisp socket (and buffer) if connection is aborted.
  Some cleanup.
  (Edi Weitz)

  Version 2.35
  Moved back the LispSocket and UnsafeLispSocket variables as global variables 
  instead of config struct variables. The struct is reset at each new request
  so the sockets were lost instead of reused.
  (Found and fixed by Edi Weitz)

  Version 2.34
  Send the SCRIPT_FILENAME variable to Lisp when it is there.

  Version 2.33
  Added a couple of new headers like "Log-Notice" and so on. 
  They are named like the corresponding log levels in httpd_log.h. 
  The "default" log level (i.e. the one sent by just "Log") has not changed.
  (contributed by Edi Weitz)

  Version 2.32
  Removed duplicate URL header sent to Lisp.
  moved server-id header before the user http headers for security.
  do not transmit any "end" header that could be sent by an malicious user
  (Thanks to Robert Macomber for the security screening)

  Version 2.31
  Put back the correct handling of replies without known content length.
  Reads only the missing number of bytes in the reply when the browser aborts the connection.

  Version 2.3
  Force Apache to read all the Lisp reply before eventually closing the socket or handling another request.
  This avoids trying to write to a closed socket or having Lisp and Apache out of sync.
  (contributed by Edi Weitz)

  Version 2.2
  Allow more than one Set-Cookie
  Remaned the win32 dll to mod_lisp.dll
  
  Version 2.1
  Added the possibility to add notes in the apache notes table
  Removed the socket reuse for the multi-threaded WIN32 apache
  Better handling of header only replies
  
  Version 2.0 beta 1
  turned mod_lisp from a quick hack to something more clean.
  added a lisp -> apache protocol for the reply 
  added a keep-alive connection between lisp and apache (the connection is not closed each time)
  
  Version 0.92
  corrected POST handling
  
  Version 0.91
  added several values : method, content-length, content-type
  
  Version 0.90
  first release

  ========================================================================= */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "plugin.h"
#include "config.h"
#include "inet_ntop_cache.h"
#include "http_chunk.h"
#include "joblist.h"
#include "connections.h"

#include "array.h"

#define MOD_LISP_VERSION "L.0.2"
#define DEFAULT_LISP_SERVER_IP "127.0.0.1"
#define DEFAULT_LISP_SERVER_ID "lighttpd"
#define DEFAULT_LISP_SERVER_PORT 3000
#define HEADER_STR_LEN 500

typedef struct {
  unsigned short LispUseHandler;  /* true iff handler should process the request */
  buffer *LispServerIP;
  unsigned short LispServerPort;
  buffer *LispServerId;
  unsigned short loglevel;
} plugin_config;

#if defined(LIGHTTPD_VERSION_ID)		       \
  && ((LIGHTTPD_VERSION_ID & (0xFF << 16)) >> 16 == 1) \
  && ((LIGHTTPD_VERSION_ID & (0xFF << 8)) >> 8 == 4) \
  && ((LIGHTTPD_VERSION_ID & 0xFF) >= 28)
#define fdevent_event_add fdevent_event_set
#endif

/* Plugin config for all request/connections. */

typedef struct {
  PLUGIN_DATA;

  buffer *LispServerIP;
  buffer *LispServerId;
  unsigned short LispServerPort;
  int LispSocket;
  unsigned short UnsafeLispSocket;
  chunkqueue *request_queue;
  buffer *response_buf;

  plugin_config **config_storage;
  plugin_config conf;
} plugin_data;

/* Init the plugin data. */ /* L-OK */
INIT_FUNC (mod_lisp_init)
{
  plugin_data *p;

  p = calloc(1, sizeof(*p));
  p->LispServerIP = buffer_init();
  p->LispServerId = buffer_init();
  p->request_queue = chunkqueue_init();
  p->response_buf = buffer_init();
  p->LispServerPort = 0;
  p->LispSocket = 0;
  p->UnsafeLispSocket = 0;
  return p;
}

/* Destroy the plugin data. */ /* L-OK */
FREE_FUNC (mod_lisp_free)
{
  plugin_data *p = p_d;
  UNUSED (srv);

  if (!p) return HANDLER_GO_ON;
  if (p->config_storage) {
    size_t i;
    for (i = 0; i < srv->config_context->used; i++) {
      plugin_config *s = p->config_storage[i];
      buffer_free(s->LispServerId);
      buffer_free(s->LispServerIP);
      free(s);
    }
    free(p->config_storage);
  }
  if (p->LispSocket) {
    close(p->LispSocket);
    srv->cur_fds--;
  }
  buffer_free(p->LispServerIP);
  buffer_free(p->LispServerId);
  chunkqueue_free(p->request_queue);
  buffer_free(p->response_buf);
  free(p);

  return HANDLER_GO_ON;
}



typedef struct {
  int fd, fde_ndx;   /* Connection-specific copy of LispSocket */
  int keep_socket;   /* False iff the socket should be closed after */
                     /* completing the request */
  unsigned long lisp_content_length;
  chunkqueue *request_queue;
  buffer *response_buf;
  size_t parse_offset;
  connection *connection;
  plugin_data *plugin;
} handler_ctx;

static handler_ctx* handler_ctx_init(plugin_data *p, connection *con) 
{
  handler_ctx *hctx;
  hctx = calloc(1, sizeof(*hctx));
  hctx->plugin = p;
  hctx->connection = con;
  hctx->fd = 0;
  hctx->keep_socket = 0;
  hctx->lisp_content_length = 0;
  hctx->request_queue = NULL;
  hctx->response_buf =  NULL;
  return hctx;
}

static void handler_ctx_free(handler_ctx *hctx)
{
  /* request_queue and response_buf are brought in from plugin data, and need
     not be initialized or freed with the connection-specific context, but reset
     them. */
  if (hctx->request_queue) chunkqueue_reset(hctx->request_queue);
  if (hctx->response_buf) buffer_reset(hctx->response_buf);
  free(hctx);
}

/* The logging interface tries to reproduce the Apache ap_log_error.
   That's ``compatibility'', sure. */

#define LOGLEVEL_EMERG     0       /* system is unusable */
#define LOGLEVEL_ALERT     1       /* action must be taken immediately */
#define LOGLEVEL_CRIT      2       /* critical conditions */
#define LOGLEVEL_ERR       3       /* error conditions */
#define LOGLEVEL_WARNING   4       /* warning conditions */
#define LOGLEVEL_NOTICE    5       /* normal but significant condition */
#define LOGLEVEL_INFO      6       /* informational */
#define LOGLEVEL_DEBUG     7       /* debug-level messages */
#define LOGLEVEL_NOERRNO   8
#define DEFAULT_LOGLEVEL   LOGLEVEL_WARNING

static const char *loglevel_string[] = {
  "emergency", "alert", "critical", "error", "warning", "notice", "info",
  "debug", ""
};

#define LOG_ERROR_MAYBE(srv, plugin, level, message)                    \
  if (level <= plugin->conf.loglevel)                                   \
    log_error_write(srv, __FILE__, __LINE__, "SSSs",                    \
                    "[", loglevel_string[level], "] ", message);        \
  else if (level == LOGLEVEL_NOERRNO)                                   \
    log_error_write(srv, __FILE__, __LINE__, "s", message)

#define MSG_LENGTH 1023
#define MSG_BUFFER (char*)msg_buffer
static char msg_buffer[MSG_LENGTH+1];

/* handle plugin config and check values */ /* L-OK */
SETDEFAULTS_FUNC (mod_lisp_set_defaults)
{
  plugin_data *p = p_d;
  size_t i = 0;
  config_values_t cv[] = {
    { "lisp.use-handler",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
    { "lisp.server-port",  NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 1 */
    { "lisp.server-id",    NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 2 */
    { "lisp.server-ip",    NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 3 */
    { "lisp.log-level",    NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 4 */
    { NULL,                NULL, T_CONFIG_UNSET,   T_CONFIG_SCOPE_UNSET }
  };

  if (!p) return HANDLER_ERROR;
  p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
  for (i = 0; i < srv->config_context->used; i++) {
    plugin_config *s;
    
    s = calloc(1, sizeof(plugin_config));
    s->LispUseHandler = 0;
    s->LispServerIP = buffer_init();
    s->LispServerId = buffer_init();
    s->LispServerPort = 0;
    s->loglevel = LOGLEVEL_NOERRNO + 1;
    p->config_storage[i] = s;
    cv[0].destination = &(s->LispUseHandler);
    cv[1].destination = &(s->LispServerPort);
    cv[2].destination = s->LispServerId;
    cv[3].destination = s->LispServerIP;
    cv[4].destination = &(s->loglevel);

    if (0 != config_insert_values_global
              (srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
      return HANDLER_ERROR;
    }

    if (i == 0) {
      if (buffer_is_empty(s->LispServerIP))
        BUFFER_COPY_STRING_CONST(s->LispServerIP, DEFAULT_LISP_SERVER_IP);
      if (buffer_is_empty(s->LispServerId))
        BUFFER_COPY_STRING_CONST(s->LispServerId, DEFAULT_LISP_SERVER_ID);
      if (s->LispServerPort == 0)
        s->LispServerPort = DEFAULT_LISP_SERVER_PORT;
      if (s->loglevel > LOGLEVEL_NOERRNO)
        s->loglevel = DEFAULT_LOGLEVEL;
    }
  }

  return HANDLER_GO_ON;
}

#define PATCH(x)  p->conf.x = s->x
static int mod_lisp_patch_connection(server *srv, connection *con, plugin_data *p)
{
  size_t i, j;
  plugin_config *s = p->config_storage[0];

  PATCH(LispUseHandler);
  PATCH(LispServerId);
  PATCH(LispServerPort);
  PATCH(LispServerIP);
  PATCH(loglevel);

  /* Skip the first, global context. */
  for (i = 1; i < srv->config_context->used; i++) {
    data_config *dc = (data_config *)srv->config_context->data[i];
    s = p->config_storage[i];
    if (!config_check_cond(srv, con, dc)) continue;  /* Condition did not match. */
    for (j = 0; j < dc->value->used; j++) {          /* Merge config. */
      data_unset *du = dc->value->data[j];
      if (buffer_is_equal_string(du->key, CONST_STR_LEN("lisp.use-handler")))
        PATCH(LispUseHandler);
      else if (buffer_is_equal_string(du->key, CONST_STR_LEN("lisp.server-id")))
        PATCH(LispServerId);
      else if (buffer_is_equal_string(du->key, CONST_STR_LEN("lisp.server-ip")))
        PATCH(LispServerIP);
      else if (buffer_is_equal_string(du->key, CONST_STR_LEN("lisp.server-port")))
        PATCH(LispServerPort);
      else if (buffer_is_equal_string(du->key, CONST_STR_LEN("lisp.log-level")))
        PATCH(loglevel);
    }
  }

  return 0;
}
#undef PATCH

static handler_t lisp_handle_fdevent(void *s, void *ctx, int revents);

URIHANDLER_FUNC (mod_lisp_start)
{
  handler_ctx *hctx;
  plugin_data *p = p_d;
  UNUSED (srv);

  mod_lisp_patch_connection(srv, con, p);

  /* Condition did not match, so the handler should not be invoked. */
  if (!p->conf.LispUseHandler) {
    LOG_ERROR_MAYBE(srv, p, LOGLEVEL_DEBUG, "Lisp handler skipped");
    return HANDLER_GO_ON;
  } else {
    LOG_ERROR_MAYBE(srv, p, LOGLEVEL_DEBUG, "Lisp handler started");  
  }
  hctx = handler_ctx_init(p, con);
  con->mode = p->id;
  con->plugin_ctx[p->id] = hctx;

  /* not found */
  return HANDLER_GO_ON;
}

REQUESTDONE_FUNC (mod_lisp_connection_close)
{
  handler_ctx *hctx;
  plugin_data *p = p_d;

  if ((hctx = con->plugin_ctx[p->id])) {
    char *socket_msg;
    if (hctx->fd == -1) {
      socket_msg = "no socket";
    } else {
      fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
      fdevent_unregister(srv->ev, hctx->fd);
      if (hctx->keep_socket) {
        socket_msg = "keep socket";
      } else {
        socket_msg = "close socket";
        close(hctx->fd);
        srv->cur_fds--;
        p->LispSocket = 0;
        p->UnsafeLispSocket = 0;
      }
    }
    snprintf(MSG_BUFFER, MSG_LENGTH,
             "Lisp process at %s:%d for %s: request processed, %s (fd=%d)",
             p->LispServerIP->ptr, p->LispServerPort, p->LispServerId->ptr,
             socket_msg, hctx->fd);
    LOG_ERROR_MAYBE(srv, p, LOGLEVEL_DEBUG, MSG_BUFFER);
    handler_ctx_free(hctx);
    con->plugin_ctx[p->id] = NULL;  
  }

  return HANDLER_GO_ON;
}

/* Open and return the socket. Cf. proxy_establish_connection() in mod_proxy.c. */
static handler_t lisp_connection_open(server *srv, handler_ctx *hctx)
{
  struct sockaddr_in addr;
  int ret;
  plugin_data *p = hctx->plugin;
  connection *con = hctx->connection;
  plugin_config conf = hctx->plugin->conf;
  int sock = hctx->fd;

/* This exclusion in the original mod_lisp had to do with multithreading
   in Win32 Apache (see change log for v. 2.1). For lighttpd, it is of
   little worth. -- B.Sm. */
/* #ifndef WIN32 */
  if (p->LispSocket) {
    if (p->UnsafeLispSocket
        || ! buffer_is_equal(conf.LispServerIP, p->LispServerIP)
        || conf.LispServerPort != p->LispServerPort) {
      mod_lisp_connection_close(srv, con, p);
      p->LispSocket = 0;
      p->UnsafeLispSocket = 0;
      buffer_reset(p->LispServerIP);
      p->LispServerPort = 0;
    } else {
      hctx->fd = p->LispSocket;
      return HANDLER_GO_ON;
    }
  }
/* #endif */

  if (hctx->fd) {
    int sockerr;
    socklen_t sockerr_len = sizeof(sockerr);
    fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
    /* try to finish the connect() */
    if (0 != getsockopt(hctx->fd, SOL_SOCKET, SO_ERROR, &sockerr, &sockerr_len)) {
      snprintf(MSG_BUFFER, MSG_LENGTH,
               "getsockopt() failed (%s)", strerror(errno));
      LOG_ERROR_MAYBE(srv, p, LOGLEVEL_ERR, MSG_BUFFER);
      return HANDLER_ERROR;
    }
    ret = sockerr ? -1 : 0;
  } else {
    if (-1 == (sock = socket(AF_INET, SOCK_STREAM, 0))) {
      snprintf(MSG_BUFFER, MSG_LENGTH,
               "socket() failed (%s)", strerror(errno));
      LOG_ERROR_MAYBE(srv, p, LOGLEVEL_ERR, MSG_BUFFER);
      return HANDLER_ERROR;
    }

    hctx->fd = sock;
    hctx->fde_ndx = -1;
    srv->cur_fds++;
    fdevent_register(srv->ev, sock, lisp_handle_fdevent, hctx);

    if (-1 == fdevent_fcntl_set(srv->ev, sock)) {
      snprintf(MSG_BUFFER, MSG_LENGTH,
               "fcntl() failed (%s)", strerror(errno));
      LOG_ERROR_MAYBE(srv, p, LOGLEVEL_ERR, MSG_BUFFER);
      return HANDLER_ERROR;
    }
    
    p->LispSocket = 0;
    p->UnsafeLispSocket = 0;
    buffer_copy_string_buffer(p->LispServerIP, conf.LispServerIP);
    buffer_copy_string_buffer(p->LispServerId, conf.LispServerId);
    p->LispServerPort = conf.LispServerPort;
    
    addr.sin_addr.s_addr = inet_addr(p->LispServerIP->ptr);
    addr.sin_port = htons(p->LispServerPort);
    addr.sin_family = AF_INET;
   
    /* Try to connect to Lisp. */
    ret = connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
#ifdef WIN32
    if (ret == SOCKET_ERROR) {
      ret = -1;
      errno = WSAGetLastError()-WSABASEERR;
    }
#endif /* WIN32 */
    if (ret == -1 && (errno == EINTR || errno == EINPROGRESS)) {
      /* As soon as something happens on the socket, this function shall be
         re-entered and follow the getsockopt branch above. */
      fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
      snprintf(MSG_BUFFER, MSG_LENGTH,
               "connection to Lisp process at %s:%d for %s delayed (%s)",
               p->LispServerIP->ptr, p->LispServerPort, p->LispServerId->ptr,
               strerror(errno));
      LOG_ERROR_MAYBE(srv, p, LOGLEVEL_DEBUG, MSG_BUFFER);
      return HANDLER_WAIT_FOR_EVENT;
    }
  }

  /* Check if we connected */
  if (ret == -1) {
    snprintf(MSG_BUFFER, MSG_LENGTH,
             "cannot connect socket to Lisp process at %s:%d for %s (%s)",
             p->LispServerIP->ptr, p->LispServerPort, p->LispServerId->ptr,
             strerror(errno));
    LOG_ERROR_MAYBE(srv, p, LOGLEVEL_ERR, MSG_BUFFER);
    hctx->fde_ndx = -1;
    mod_lisp_connection_close(srv, con, p);
    /* reset the enviroment and restart the sub-request */	
    connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);
    con->http_status = 503;
    con->mode = DIRECT;
    joblist_append(srv, con);
    return HANDLER_FINISHED;
  }

  p->LispSocket = sock;
  snprintf(MSG_BUFFER, MSG_LENGTH,
           "opened socket fd=%d to Lisp process at %s:%d for %s",
           sock, p->LispServerIP->ptr, p->LispServerPort, p->LispServerId->ptr);
  LOG_ERROR_MAYBE(srv, p, LOGLEVEL_DEBUG, MSG_BUFFER);
  return HANDLER_GO_ON;
}

static int get_remote_port(server *srv, connection *con)
{
  sock_addr remote_addr;
  socklen_t len;
  UNUSED (srv);

  if (con->fd > 0
      && getpeername(con->fd, &(remote_addr.plain), &len) == 0) {
    switch (remote_addr.plain.sa_family) {
    case AF_INET:
      return (int)(ntohs(remote_addr.ipv4.sin_port));
    case AF_INET6:
      return (int)(ntohs(remote_addr.ipv6.sin6_port));
    default:
      break;
    }
  }
  return 0;
}

static const char* get_local_ip(server *srv, connection *con)
{
  sock_addr local_addr;
  socklen_t len;

  if (con->fd > 0
      && getsockname(con->fd, &(local_addr.plain), &len) == 0) {
    return inet_ntop_cache_get_ip(srv, &local_addr);
  }
  return "?.?.?.?";
}

static void prepare_lisp_request (server *srv, handler_ctx *hctx)
{
  size_t i;
  buffer *buf;
  connection *con = hctx->connection;
  plugin_data *p = hctx->plugin;
  chunkqueue *hr_cq = hctx->request_queue;

  buf = chunkqueue_get_append_buffer(hr_cq);

#define APPEND_HEADER(k, vt, v)            \
  BUFFER_APPEND_STRING_CONST(buf, k);      \
  BUFFER_APPEND_STRING_CONST(buf, "\n");   \
  buffer_append_##vt(buf, v);              \
  BUFFER_APPEND_STRING_CONST(buf, "\n")

#define KEY_IS(string) \
  (buffer_caseless_compare(CONST_BUF_LEN(ds->key), CONST_STR_LEN(string)) == 0)

#if 0
  for (i = 0; i < srv->srv_sockets.used; i++) {
      log_error_write(srv, __FILE__, __LINE__, "sd<S>", 
                      "srv_sockets", i,
                      inet_ntop_cache_get_ip(srv, &(srv->srv_sockets.ptr[i]->addr)));
  }
#endif

  /* Mod_lisp configuration and connection info. */
  APPEND_HEADER("server-id", string_buffer, p->LispServerId);
  APPEND_HEADER("server-baseversion", string, PACKAGE_STRING);
  APPEND_HEADER("modlisp-version", string, MOD_LISP_VERSION);
  /* Server/connection configuration info. */
  APPEND_HEADER("url", string_buffer, con->request.uri);
  APPEND_HEADER("method", string, get_http_method_name(con->request.http_method));
  APPEND_HEADER("script-filename", string_buffer, con->physical.path);
  APPEND_HEADER("server-protocol", string, get_http_version_name(con->request.http_version));
  APPEND_HEADER("remote-ip-port", long, get_remote_port(srv, con));
  APPEND_HEADER("server-ip-port", long, srv->srvconf.port);
  APPEND_HEADER("remote-ip-addr", string, inet_ntop_cache_get_ip(srv, &(con->dst_addr)));
  APPEND_HEADER("server-ip-addr", string, get_local_ip(srv, con));
  if (con->request.http_content_type) {
    APPEND_HEADER("content-type", string, con->request.http_content_type);
  }
  if (con->request.content_length) {
    APPEND_HEADER("content-length", long, con->request.content_length);
  }
#ifdef USE_OPENSSL
  if (con->ssl) {
    SSL_SESSION *sess = SSL_get_session(con->ssl);
    if (sess && sess->session_id_length) {
      BUFFER_APPEND_STRING_CONST(buf, "ssl-session-id\n");
      buffer_append_string_len(buf, (char*)(sess->session_id), (size_t)(sess->session_id_length));
      BUFFER_APPEND_STRING_CONST(buf, "\n");
    }
  }
#endif
  /* Request headers */
  for (i = 0; i < con->request.headers->used; i++) {
    data_string *ds = (data_string*) con->request.headers->data[i];
    if (ds->value->used && ds->key->used) {
      if (KEY_IS("End")) {
        APPEND_HEADER("end-header", string_buffer, ds->value);
      } else {
        buffer_append_string_buffer(buf, ds->key);
        BUFFER_APPEND_STRING_CONST(buf, "\n");
        buffer_append_string_buffer(buf, ds->value);
        BUFFER_APPEND_STRING_CONST(buf, "\n");
      }
    }
  }
  /* End-of-headers */
  BUFFER_APPEND_STRING_CONST(buf, "end\n");
  hr_cq->bytes_in += buf->used - 1;

#undef APPEND_HEADER
#undef KEY_IS

  /* If there is an entity in the request, send it, too. */
  if (con->request.content_length) {
    chunkqueue *req_cq = con->request_content_queue;
    chunk *req_c;
    off_t offset;
    for (offset = 0, req_c = req_cq->first;    /* something to send? */
         offset != req_cq->bytes_in;
         req_c = req_c->next) {
      off_t weWant = req_cq->bytes_in - offset;
      off_t weHave = 0;
      /* We announce toWrite octects.  Now take all the request_content chunk
         that we need to fill this request. */  
      switch (req_c->type) {
      case FILE_CHUNK:
        weHave = req_c->file.length - req_c->offset;
        if (weHave > weWant) weHave = weWant;
        chunkqueue_append_file(hr_cq, req_c->file.name, req_c->offset, weHave);
        req_c->offset += weHave;
        req_cq->bytes_out += weHave;
        hr_cq->bytes_in += weHave;
        break;
      case MEM_CHUNK:
        /* append to the buffer */
        weHave = req_c->mem->used - 1 - req_c->offset;
        if (weHave > weWant) weHave = weWant;
        buf = chunkqueue_get_append_buffer(hr_cq);
        buffer_append_memory(buf, req_c->mem->ptr + req_c->offset, weHave);
        buf->used++; /* add virtual \0 */
        req_c->offset += weHave;
        req_cq->bytes_out += weHave;
        hr_cq->bytes_in += weHave;
        break;
      default:
        break;
      }
      offset += weHave;
    }
  }
}

static handler_t mod_lisp_send_request (server *srv, handler_ctx *hctx)
{
  int ret;
  connection *con = hctx->connection;
  plugin_data *p = hctx->plugin;
  chunkqueue *hr_cq = hctx->request_queue;

  if (!hr_cq->bytes_in) {
    prepare_lisp_request(srv, hctx);
    snprintf(MSG_BUFFER, MSG_LENGTH,
             "Lisp process at %s:%d for %s: ready to send request",
             p->LispServerIP->ptr, p->LispServerPort, p->LispServerId->ptr);
    LOG_ERROR_MAYBE(srv, p, LOGLEVEL_DEBUG, MSG_BUFFER);
  }

  ret = srv->network_backend_write(srv, con, hctx->fd, hr_cq); 
  chunkqueue_remove_finished_chunks(hr_cq);
  if (-1 == ret) {
    if (errno == EAGAIN && errno == EINTR) {
      fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
      return HANDLER_WAIT_FOR_EVENT;
    } else {
      snprintf(MSG_BUFFER, MSG_LENGTH,
               "failed to send request to Lisp process at %s:%d for %s (%s)",
               p->LispServerIP->ptr, p->LispServerPort, p->LispServerId->ptr,
               strerror(errno));
      LOG_ERROR_MAYBE(srv, p, LOGLEVEL_ERR, MSG_BUFFER);
      return HANDLER_ERROR;
    }
  }
  if (hr_cq->bytes_out == hr_cq->bytes_in) {
    fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
    fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
  } else {
    fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
  }
  return HANDLER_WAIT_FOR_EVENT;
}

SUBREQUEST_FUNC (mod_lisp_handle_subrequest)
{
  handler_ctx *hctx;
  handler_t ret;
  plugin_data *p;

  p = p_d;
  if (con->mode != p->id) return HANDLER_GO_ON;
  if (con->file_started) return HANDLER_FINISHED;
  if (! (hctx = con->plugin_ctx[p->id])) return HANDLER_ERROR;
  mod_lisp_patch_connection(srv, con, p);

  /* We are not yet connected to Lisp. */
  if (! hctx->request_queue) {
    if ((ret = lisp_connection_open(srv, hctx)) != HANDLER_GO_ON)
      return ret;
    hctx->request_queue = p->request_queue;
    hctx->request_queue->bytes_in = 0;
  }
  p->UnsafeLispSocket = 1;
  /* We are connected, but the request has not yet been fully sent out. */
  if (! hctx->response_buf) {
    if ((ret = mod_lisp_send_request(srv, hctx)) != HANDLER_WAIT_FOR_EVENT)
      return ret;
    hctx->response_buf = p->response_buf;
    hctx->parse_offset = 0;
  }
  /* Wait for incoming data. */
  return HANDLER_WAIT_FOR_EVENT;
}

static int parse_lisp_response(server *srv, handler_ctx *hctx)
{
  int copy_header;
  char *end_ptr, *prev_ptr, *ptr, *key, *value;
  size_t key_len = 0;
  connection *con = hctx->connection;
  plugin_data *p = hctx->plugin;

#define KEY_IS(k) \
  (key_len+1 == sizeof(k) && strncasecmp(key, k, key_len) == 0)

  end_ptr = hctx->response_buf->ptr + hctx->response_buf->used;
  prev_ptr = hctx->response_buf->ptr + hctx->parse_offset;
  for (key = value = NULL, ptr = strchr(prev_ptr, '\n');
       ptr && (ptr < end_ptr);
       ptr = strchr(ptr, '\n')) {
    if (!key) {
      key = prev_ptr;
      key_len = ptr - prev_ptr;
#if 0
  strncpy(MSG_BUFFER, key, key_len);
  msg_buffer[key_len] = '\0';
  log_error_write(srv, __FILE__, __LINE__, "s<S>", 
                  "parse_lisp_response: key", MSG_BUFFER);
#endif
      if (KEY_IS("End")) {
        hctx->parse_offset = ++ptr - hctx->response_buf->ptr;
        return 1;               /* 1 = body (if any) has been reached. */
      } else {
        ++ptr;
      }
    } else {
      value = key + key_len + 1;
      *ptr = '\0';
#if 0
  strcpy(MSG_BUFFER, prev_ptr);
  msg_buffer[key_len] = ':';
  log_error_write(srv, __FILE__, __LINE__, "s<S>", 
                  "parse_lisp_response: key+val", MSG_BUFFER);
#endif
      prev_ptr = ++ptr;
      copy_header = 0;
      /* Dispatch on key. */
      if (KEY_IS("Status")) {
        con->http_status = atoi(value);
        con->parsed_response |= HTTP_STATUS;
      } else if (KEY_IS("Date")) {
        con->parsed_response |= HTTP_DATE;
        copy_header = 1;
      } else if (KEY_IS("Location")) {
        con->parsed_response |= HTTP_LOCATION;
        copy_header = 1;
      } else if (KEY_IS("Connection")) {
        /* Relax. */
      } else if (KEY_IS("Content-Length")) {
        hctx->lisp_content_length = con->response.content_length =
          strtoul(value, NULL, 10);
        con->parsed_response |= HTTP_CONTENT_LENGTH;
        copy_header = 1;
      } else if (KEY_IS("Lisp-Content-Length")) {
        hctx->lisp_content_length = strtoul(value, NULL, 10);
      } else if (KEY_IS("Keep-Socket")) {
        hctx->keep_socket = atoi(value);
      } else if (KEY_IS("Log-Emerg")) {
        LOG_ERROR_MAYBE(srv, p, LOGLEVEL_EMERG, value);
      } else if (KEY_IS("Log-Alert")) {
        LOG_ERROR_MAYBE(srv, p, LOGLEVEL_ALERT, value);
      } else if (KEY_IS("Log-Crit")) {
        LOG_ERROR_MAYBE(srv, p, LOGLEVEL_CRIT, value);
      } else if (KEY_IS("Log-Error")) {
        LOG_ERROR_MAYBE(srv, p, LOGLEVEL_ERR, value);
      } else if (KEY_IS("Log-Warning")) {
        LOG_ERROR_MAYBE(srv, p, LOGLEVEL_WARNING, value);
      } else if (KEY_IS("Log-Notice")) {
        LOG_ERROR_MAYBE(srv, p, LOGLEVEL_NOTICE, value);
      } else if (KEY_IS("Log-Info")) {
        LOG_ERROR_MAYBE(srv, p, LOGLEVEL_INFO, value);
      } else if (KEY_IS("Log-Debug")) {
        LOG_ERROR_MAYBE(srv, p, LOGLEVEL_DEBUG, value);
      } else if (KEY_IS("Log")) {
        LOG_ERROR_MAYBE(srv, p, LOGLEVEL_ERR, value);
      } else if (KEY_IS("Note")) {
        /* This is Apache-specific functionality.  Just ignore. */
      } else {
        copy_header = 1;
      }
      /* Populate response headers. */
      if (copy_header) {
        data_string *ds =
          (data_string*) array_get_unused_element(con->response.headers,
                                                  TYPE_STRING);
        if (!ds) ds = data_response_init();
        buffer_copy_string_len(ds->key, key, key_len);
        buffer_copy_string_len(ds->value, value, ptr - value - 1);
        array_insert_unique(con->response.headers, (data_unset*) ds);
      }
      key = value = NULL;
    }
  }

#undef KEY_IS

  hctx->parse_offset = prev_ptr - hctx->response_buf->ptr;
  return 0;                     /* 0 = end header (i.e. body) not reached yet. */
}

static handler_t mod_lisp_prepare_response (server *srv, handler_ctx *hctx)
{
  int bytes;
  ssize_t read_bytes; 
  plugin_data *p    = hctx->plugin;
  connection *con   = hctx->connection;
  buffer *buf       = hctx->response_buf;
  
  /* Check how much we have to read. */
  if (ioctl(hctx->fd, FIONREAD, &bytes)) {
    snprintf(MSG_BUFFER, MSG_LENGTH, "ioctl() failed (%s)", strerror(errno));
    LOG_ERROR_MAYBE(srv, p, LOGLEVEL_ERR, MSG_BUFFER);
    snprintf(MSG_BUFFER, MSG_LENGTH, "ioctl() failed (%s)", strerror(errno));
    LOG_ERROR_MAYBE(srv, p, LOGLEVEL_ERR, MSG_BUFFER);
    return HANDLER_ERROR;
  } else {
    snprintf(MSG_BUFFER, MSG_LENGTH, "%d bytes from Lisp", bytes);
    LOG_ERROR_MAYBE(srv, p, LOGLEVEL_DEBUG, MSG_BUFFER);
  }
  if (bytes > 0) {
    /* Avoid too small buffer. */
    if (buf->used == 0) {
      buffer_prepare_append(buf, bytes + 1);
      buf->used = 1;
    } else {
      buffer_prepare_append(buf, buf->used + bytes);
    }
    /* Read from socket. */
    if (-1 == (read_bytes = read(hctx->fd, buf->ptr + buf->used - 1, bytes))) {
      snprintf(MSG_BUFFER, MSG_LENGTH,
               "unexpected EOF from Lisp process on fd %d (%s)",
               hctx->fd, strerror(errno));
      LOG_ERROR_MAYBE(srv, p, LOGLEVEL_ERR, MSG_BUFFER);
      return HANDLER_ERROR;
    }
    assert(read_bytes);         /* This should be caught by the bytes > 0 above. */
    con->got_response = 1;
    buf->used += read_bytes;
    buf->ptr[buf->used - 1] = '\0';
    if (! con->file_started) {
      /* Parse the response headers: return value 1 means that the end header
         has been reached, 0 means otherwise.  Store the offset of the unparsed
         portion in hctx->parse_offset. */
      if ((con->file_started = parse_lisp_response(srv, hctx))) {
        int body_len = buf->used - hctx->parse_offset;
        /* Rectify HTTP status. */
        if (!(con->parsed_response & HTTP_STATUS)
            || con->http_status <= 0) {
          con->http_status = 502; /* mod_lisp is still a kind of proxy. */
          con->parsed_response |= HTTP_STATUS;
        }
        /* Unset content length and return immediately if the request method is
           a no-header one. */
        if (con->request.http_method == HTTP_METHOD_HEAD /* Any others? */ ) {
          con->parsed_response &= ~HTTP_CONTENT_LENGTH;
          con->file_finished = 1;
          http_chunk_append_mem(srv, con, NULL, 0);
          joblist_append(srv, con); /* Connection to state ERROR */
          return HANDLER_FINISHED;
        } else {
          /* Enable chunked-transfer-encoding if no content-length supplied
             (actually, this shouldn't ever happen). */
          if (con->request.http_version == HTTP_VERSION_1_1 &&
              !(con->parsed_response & HTTP_CONTENT_LENGTH))
            con->response.transfer_encoding = HTTP_TRANSFER_ENCODING_CHUNKED;
          if (body_len > 0)
            http_chunk_append_mem(srv, con, buf->ptr + hctx->parse_offset,
                                  body_len);
          buf->used = 0;
          hctx->parse_offset = 0;
        }
      }
    } else {
      http_chunk_append_mem(srv, con, buf->ptr, buf->used);
      joblist_append(srv, con); /* Connection to state WRITE */
      buf->used = 0;
    }
  } else {
    con->file_finished = 1;     /* Reading from upstream done */
    http_chunk_append_mem(srv, con, "\n ", 2);
    http_chunk_append_mem(srv, con, NULL, 0);
    joblist_append(srv, con);   /* Connection to state RESPONSE_END */
    return HANDLER_FINISHED;
  }

  return HANDLER_GO_ON;
}

static handler_t lisp_handle_fdevent(void *s, void *ctx, int revents)
{
  connection *con;
  plugin_data *p;
  server *srv = (server*)s;
  handler_ctx *hctx = (handler_ctx*)ctx;
  int handled = 0;

  con = hctx->connection; 
  p = hctx->plugin;

  snprintf(MSG_BUFFER, MSG_LENGTH,
           "fdevent from Lisp process on fd %d (revents=%d)", hctx->fd, revents);
  LOG_ERROR_MAYBE(srv, p, LOGLEVEL_DEBUG, MSG_BUFFER);

  /* Lisp is ready to read the request. */
  if ((revents & FDEVENT_OUT) && !hctx->response_buf) {
    handled = 1;
    return mod_lisp_handle_subrequest(srv, con, p);
  }
  /* The request has been sent, Lisp has responded.  Now prepare the response to
     be passed to the incoming connection. */
  if ((revents & FDEVENT_IN) && hctx->response_buf) {
    handler_t ret;
    handled = 1;
    switch ((ret = mod_lisp_prepare_response(srv, hctx))) {
    case HANDLER_ERROR:
      if (con->file_started) {
        /* Response might have been already started, kill the connection. */
        connection_set_state(srv, con, CON_STATE_ERROR);
      } else {
        /* Nothing has been sent out yet, send a 500. */
        connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);
        con->http_status = 500;
        con->mode = DIRECT;
      }
      joblist_append(srv, con);
      return HANDLER_FINISHED;
    case HANDLER_GO_ON:
      break;
    case HANDLER_FINISHED:
      mod_lisp_connection_close(srv, con, p);
      joblist_append(srv, con);
    default:
      return ret;
    }
  }
  /* Lisp hung up. */
  if (revents & FDEVENT_HUP) {
    handled = 1;
    if (! hctx->request_queue) {
      /* connect() -> EINPROGRESS -> HUP */
      mod_lisp_connection_close(srv, con, p);
      joblist_append(srv, con);
      con->http_status = 503;
      con->mode = DIRECT;
      return HANDLER_FINISHED;
    } else {
      con->file_finished = 1;
      mod_lisp_connection_close(srv, con, p);
      joblist_append(srv, con);
    }
  }
  /* Socket error. */
  if (revents & FDEVENT_ERR) {
    handled = 1;
    mod_lisp_connection_close(srv, con, p);
    joblist_append(srv, con);
  }

  if (!handled) {
    snprintf(MSG_BUFFER, MSG_LENGTH,
             "fdevent on lisp %d (revents=%d): unhandled", hctx->fd, revents);
    LOG_ERROR_MAYBE(srv, p, LOGLEVEL_DEBUG, MSG_BUFFER);
  }
  return HANDLER_FINISHED;
}

/* this function is called at dlopen() time and inits the callbacks */
int mod_lisp_plugin_init(plugin *p)
{
  p->version = LIGHTTPD_VERSION_ID;
  p->name = buffer_init_string("lisp");

  p->init = mod_lisp_init;
  p->cleanup = mod_lisp_free;
  p->set_defaults = mod_lisp_set_defaults;
  p->handle_uri_clean  = mod_lisp_start;
  p->handle_subrequest = mod_lisp_handle_subrequest;
  p->connection_reset = mod_lisp_connection_close; /* end of req-resp cycle */
  p->handle_connection_close = mod_lisp_connection_close; /* end of client connection */

  p->data = NULL;

  return 0;
}
