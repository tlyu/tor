/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control_proto.c
 * \brief Implement control protocol encoding and decoding
 **/

#include <stdarg.h>

#include "core/or/or.h"

#define CONTROL_PROTO_PRIVATE
#include "core/mainloop/connection.h"
#include "feature/control/control.h"
#include "feature/control/control_connection_st.h"
#include "feature/control/control_proto.h"

/** Given a <b>len</b>-character string in <b>data</b>, made of lines
 * terminated by CRLF, allocate a new string in *<b>out</b>, and copy the
 * contents of <b>data</b> into *<b>out</b>, adding a period before any period
 * that appears at the start of a line, and adding a period-CRLF line at
 * the end. Replace all LF characters sequences with CRLF.  Return the number
 * of bytes in *<b>out</b>.
 */
size_t
write_escaped_data(const char *data, size_t len, char **out)
{
  tor_assert(len < SIZE_MAX - 9);
  size_t sz_out = len+8+1;
  char *outp;
  const char *start = data, *end;
  size_t i;
  int start_of_line;
  for (i=0; i < len; ++i) {
    if (data[i] == '\n') {
      sz_out += 2; /* Maybe add a CR; maybe add a dot. */
      if (sz_out >= SIZE_T_CEILING) {
        log_warn(LD_BUG, "Input to write_escaped_data was too long");
        *out = tor_strdup(".\r\n");
        return 3;
      }
    }
  }
  *out = outp = tor_malloc(sz_out);
  end = data+len;
  start_of_line = 1;
  while (data < end) {
    if (*data == '\n') {
      if (data > start && data[-1] != '\r')
        *outp++ = '\r';
      start_of_line = 1;
    } else if (*data == '.') {
      if (start_of_line) {
        start_of_line = 0;
        *outp++ = '.';
      }
    } else {
      start_of_line = 0;
    }
    *outp++ = *data++;
  }
  if (outp < *out+2 || fast_memcmp(outp-2, "\r\n", 2)) {
    *outp++ = '\r';
    *outp++ = '\n';
  }
  *outp++ = '.';
  *outp++ = '\r';
  *outp++ = '\n';
  *outp = '\0'; /* NUL-terminate just in case. */
  tor_assert(outp >= *out);
  tor_assert((size_t)(outp - *out) <= sz_out);
  return outp - *out;
}

/** Given a <b>len</b>-character string in <b>data</b>, made of lines
 * terminated by CRLF, allocate a new string in *<b>out</b>, and copy
 * the contents of <b>data</b> into *<b>out</b>, removing any period
 * that appears at the start of a line, and replacing all CRLF sequences
 * with LF.   Return the number of
 * bytes in *<b>out</b>. */
size_t
read_escaped_data(const char *data, size_t len, char **out)
{
  char *outp;
  const char *next;
  const char *end;

  *out = outp = tor_malloc(len+1);

  end = data+len;

  while (data < end) {
    /* we're at the start of a line. */
    if (*data == '.')
      ++data;
    next = memchr(data, '\n', end-data);
    if (next) {
      size_t n_to_copy = next-data;
      /* Don't copy a CR that precedes this LF. */
      if (n_to_copy && *(next-1) == '\r')
        --n_to_copy;
      memcpy(outp, data, n_to_copy);
      outp += n_to_copy;
      data = next+1; /* This will point at the start of the next line,
                      * or the end of the string, or a period. */
    } else {
      memcpy(outp, data, end-data);
      outp += (end-data);
      *outp = '\0';
      return outp - *out;
    }
    *outp++ = '\n';
  }

  *outp = '\0';
  return outp - *out;
}

/** If the first <b>in_len_max</b> characters in <b>start</b> contain a
 * double-quoted string with escaped characters, return the length of that
 * string (as encoded, including quotes).  Otherwise return -1. */
static inline int
get_escaped_string_length(const char *start, size_t in_len_max,
                          int *chars_out)
{
  const char *cp, *end;
  int chars = 0;

  if (*start != '\"')
    return -1;

  cp = start+1;
  end = start+in_len_max;

  /* Calculate length. */
  while (1) {
    if (cp >= end) {
      return -1; /* Too long. */
    } else if (*cp == '\\') {
      if (++cp == end)
        return -1; /* Can't escape EOS. */
      ++cp;
      ++chars;
    } else if (*cp == '\"') {
      break;
    } else {
      ++cp;
      ++chars;
    }
  }
  if (chars_out)
    *chars_out = chars;
  return (int)(cp - start+1);
}

/** As decode_escaped_string, but does not decode the string: copies the
 * entire thing, including quotation marks. */
const char *
extract_escaped_string(const char *start, size_t in_len_max,
                       char **out, size_t *out_len)
{
  int length = get_escaped_string_length(start, in_len_max, NULL);
  if (length<0)
    return NULL;
  *out_len = length;
  *out = tor_strndup(start, *out_len);
  return start+length;
}

/** Given a pointer to a string starting at <b>start</b> containing
 * <b>in_len_max</b> characters, decode a string beginning with one double
 * quote, containing any number of non-quote characters or characters escaped
 * with a backslash, and ending with a final double quote.  Place the resulting
 * string (unquoted, unescaped) into a newly allocated string in *<b>out</b>;
 * store its length in <b>out_len</b>.  On success, return a pointer to the
 * character immediately following the escaped string.  On failure, return
 * NULL. */
const char *
decode_escaped_string(const char *start, size_t in_len_max,
                   char **out, size_t *out_len)
{
  const char *cp, *end;
  char *outp;
  int len, n_chars = 0;

  len = get_escaped_string_length(start, in_len_max, &n_chars);
  if (len<0)
    return NULL;

  end = start+len-1; /* Index of last quote. */
  tor_assert(*end == '\"');
  outp = *out = tor_malloc(len+1);
  *out_len = n_chars;

  cp = start+1;
  while (cp < end) {
    if (*cp == '\\')
      ++cp;
    *outp++ = *cp++;
  }
  *outp = '\0';
  tor_assert((outp - *out) == (int)*out_len);

  return end+1;
}

/** Append a NUL-terminated string <b>s</b> to the end of
 * <b>conn</b>-\>outbuf.
 */
void
connection_write_str_to_buf(const char *s, control_connection_t *conn)
{
  size_t len = strlen(s);
  connection_buf_add(s, len, TO_CONN(conn));
}

/** Acts like sprintf, but writes its formatted string to the end of
 * <b>conn</b>-\>outbuf. */
void
connection_printf_to_buf(control_connection_t *conn, const char *format, ...)
{
  va_list ap;
  char *buf = NULL;
  int len;

  va_start(ap,format);
  len = tor_vasprintf(&buf, format, ap);
  va_end(ap);

  if (len < 0) {
    log_err(LD_BUG, "Unable to format string for controller.");
    tor_assert(0);
  }

  connection_buf_add(buf, (size_t)len, TO_CONN(conn));

  tor_free(buf);
}

/** Write a reply to the control channel. */
void
control_write_reply(control_connection_t *conn, int code, int c, const char *s)
{
  connection_printf_to_buf(conn, "%03d%c%s\r\n", code, c, s);
}

/** Write a formatted reply to the control channel. */
void
control_vprintf_reply(control_connection_t *conn, int code, int c,
                      const char *fmt, va_list ap)
{
  char *buf = NULL;
  int len;

  len = tor_vasprintf(&buf, fmt, ap);
  if (len < 0) {
    log_err(LD_BUG, "Unable to format string for controller.");
    tor_assert(0);
  }
  control_write_reply(conn, code, c, buf);
  tor_free(buf);
}

/** Write a single-line reply */
void
control_write_onereply(control_connection_t *conn, int code, const char *s)
{
  control_write_reply(conn, code, ' ', s);
}

/** Write a single-line formatted reply */
void
control_printf_onereply(control_connection_t *conn, int code,
                        const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  control_vprintf_reply(conn, code, ' ', fmt, ap);
  va_end(ap);
}

/** Write the middle line of a multi-line reply */
void
control_write_midreply(control_connection_t *conn, int code, const char *s)
{
  control_write_reply(conn, code, '-', s);
}

/** Write a formatted middle line of a multi-line reply */
void
control_printf_midreply(control_connection_t *conn, int code, const char *fmt,
                        ...)
{
  va_list ap;

  va_start(ap, fmt);
  control_vprintf_reply(conn, code, '-', fmt, ap);
  va_end(ap);
}

/** Write the initial line of an escaped-data reply */
void
control_write_datareply(control_connection_t *conn, int code, const char *s)
{
  control_write_reply(conn, code, '+', s);
}

/** Write a formatted initial line of an escaped-data reply */
void
control_printf_datareply(control_connection_t *conn, int code, const char *fmt,
                         ...)
{
  va_list ap;

  va_start(ap, fmt);
  control_vprintf_reply(conn, code, '+', fmt, ap);
  va_end(ap);
}

/** Write an escaped-data reply */
void
control_write_data(control_connection_t *conn, const char *data)
{
  char *esc = NULL;
  size_t esc_len;

  esc_len = write_escaped_data(data, strlen(data), &esc);
  connection_buf_add(esc, esc_len, TO_CONN(conn));
  tor_free(esc);
}
