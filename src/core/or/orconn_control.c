/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "core/or/connection_or.h"
#include "core/or/or_connection_st.h"

static void orconn_target_get_name(char *buf, size_t len,
                                   or_connection_t *conn);

/** Figure out the best name for the target router of an OR connection
 * <b>conn</b>, and write it into the <b>len</b>-character buffer
 * <b>name</b>. */
static void
orconn_target_get_name(char *name, size_t len, or_connection_t *conn)
{
  const node_t *node = node_get_by_id(conn->identity_digest);
  if (node) {
    tor_assert(len > MAX_VERBOSE_NICKNAME_LEN);
    node_get_verbose_nickname(node, name);
  } else if (! tor_digest_is_zero(conn->identity_digest)) {
    name[0] = '$';
    base16_encode(name+1, len-1, conn->identity_digest,
                  DIGEST_LEN);
  } else {
    tor_snprintf(name, len, "%s:%d",
                 conn->base_.address, conn->base_.port);
  }
}

char *
orconn_getinfo(void)
{
  smartlist_t *conns = get_connection_array();
  smartlist_t *status = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(conns, connection_t *, base_conn) {
    const char *state;
    char name[128];
    or_connection_t *conn;
    if (base_conn->type != CONN_TYPE_OR || base_conn->marked_for_close)
      continue;
    conn = TO_OR_CONN(base_conn);
    if (conn->base_.state == OR_CONN_STATE_OPEN)
      state = "CONNECTED";
    else if (conn->nickname)
      state = "LAUNCHED";
    else
      state = "NEW";
    orconn_target_get_name(name, sizeof(name), conn);
    smartlist_add_asprintf(status, "%s %s", name, state);
  } SMARTLIST_FOREACH_END(base_conn);
  *answer = smartlist_join_strings(status, "\r\n", 0, NULL);
  SMARTLIST_FOREACH(status, char *, cp, tor_free(cp));
  smartlist_free(status);
}

/** Called when the status of an OR connection <b>conn</b> changes: tell any
 * interested control connections. <b>tp</b> is the new status for the
 * connection.  If <b>conn</b> has just closed or failed, then <b>reason</b>
 * may be the reason why.
 */
int
control_event_or_conn_status(or_connection_t *conn, or_conn_status_event_t tp,
                             int reason)
{
  int ncircs = 0;
  const char *status;
  char name[128];
  char ncircs_buf[32] = {0}; /* > 8 + log10(2^32)=10 + 2 */

  if (!EVENT_IS_INTERESTING(EVENT_OR_CONN_STATUS))
    return 0;

  switch (tp)
    {
    case OR_CONN_EVENT_LAUNCHED: status = "LAUNCHED"; break;
    case OR_CONN_EVENT_CONNECTED: status = "CONNECTED"; break;
    case OR_CONN_EVENT_FAILED: status = "FAILED"; break;
    case OR_CONN_EVENT_CLOSED: status = "CLOSED"; break;
    case OR_CONN_EVENT_NEW: status = "NEW"; break;
    default:
      log_warn(LD_BUG, "Unrecognized status code %d", (int)tp);
      return 0;
    }
  if (conn->chan) {
    ncircs = circuit_count_pending_on_channel(TLS_CHAN_TO_BASE(conn->chan));
  } else {
    ncircs = 0;
  }
  ncircs += connection_or_get_num_circuits(conn);
  if (ncircs && (tp == OR_CONN_EVENT_FAILED || tp == OR_CONN_EVENT_CLOSED)) {
    tor_snprintf(ncircs_buf, sizeof(ncircs_buf), " NCIRCS=%d", ncircs);
  }

  orconn_target_get_name(name, sizeof(name), conn);
  send_control_event(EVENT_OR_CONN_STATUS,
                              "650 ORCONN %s %s%s%s%s ID=%"PRIu64"\r\n",
                              name, status,
                              reason ? " REASON=" : "",
                              orconn_end_reason_to_control_string(reason),
                              ncircs_buf,
                              (conn->base_.global_identifier));

  return 0;
}
