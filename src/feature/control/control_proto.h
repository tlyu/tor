/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control_proto.h
 * \brief Header file for control_proto.c.
 *
 * Functions to read and write control protocol messages.
 **/

#ifndef TOR_CONTROL_PROTO_H
#define TOR_CONTROL_PROTO_H

#include <stdarg.h>

#include "core/or/or.h"

#include "lib/cc/compat_compiler.h"

#if defined(CONTROL_PRIVATE) || defined(CONTROL_PROTO_PRIVATE)
/*
 * These eventually should only be used by control_proto.c.
 */
size_t write_escaped_data(const char *data, size_t len, char **out);
size_t read_escaped_data(const char *data, size_t len, char **out);
const char *extract_escaped_string(const char *start, size_t in_len_max,
                                   char **out, size_t *out_len);
const char *decode_escaped_string(const char *start, size_t in_len_max,
                                  char **out, size_t *out_len);

void connection_write_str_to_buf(const char *s, control_connection_t *conn);
void connection_printf_to_buf(control_connection_t *conn,
                              const char *format, ...)
  CHECK_PRINTF(2,3);
#endif  /* defined(CONTROL_PRIVATE) || defined(CONTROL_PROTO_PRIVATE) */

void control_write_reply(control_connection_t *conn, int code, int c,
                         const char *s);
void control_vprintf_reply(control_connection_t *conn, int code, int c,
                           const char *fmt, va_list ap)
  CHECK_PRINTF(4, 0);
void control_write_onereply(control_connection_t *conn, int code,
                            const char *s);
void control_printf_onereply(control_connection_t *conn, int code,
                             const char *fmt, ...)
  CHECK_PRINTF(3, 4);
void control_write_midreply(control_connection_t *conn, int code,
                            const char *s);
void control_printf_midreply(control_connection_t *conn, int code,
                             const char *fmt,
                             ...)
  CHECK_PRINTF(3, 4);
void control_write_datareply(control_connection_t *conn, int code,
                             const char *s);
void control_printf_datareply(control_connection_t *conn, int code,
                              const char *fmt,
                              ...)
  CHECK_PRINTF(3, 4);
void control_write_data(control_connection_t *conn, const char *data);

#endif  /* defined(TOR_CONTROL_PROTO_H) */
