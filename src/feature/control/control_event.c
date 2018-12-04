/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control_event.c
 * \brief Implement sending async events on the control port
 *
 * Individual event implementations call into these functions to send
 * events to the control port.
 **/

#include "core/or/or.h"

/** Yield true iff <b>s</b> is the state of a control_connection_t that has
 * finished authentication and is accepting commands. */
#define STATE_IS_OPEN(s) ((s) == CONTROL_CONN_STATE_OPEN)

/** Bitfield: The bit 1&lt;&lt;e is set if <b>any</b> open control
 * connection is interested in events of type <b>e</b>.  We use this
 * so that we can decide to skip generating event messages that nobody
 * has interest in without having to walk over the global connection
 * list to find out.
 **/
typedef uint64_t event_mask_t;

/** An event mask of all the events that any controller is interested in
 * receiving. */
static event_mask_t global_event_mask = 0;

/** Macro: true if any control connection is interested in events of type
 * <b>e</b>. */
#define EVENT_IS_INTERESTING(e) \
  (!! (global_event_mask & EVENT_MASK_(e)))

/** Macro: true if any event from the bitfield 'e' is interesting. */
#define ANY_EVENT_IS_INTERESTING(e) \
  (!! (global_event_mask & (e)))

/** Helper: clear bandwidth counters of all origin circuits. */
static void
clear_circ_bw_fields(void)
{
  origin_circuit_t *ocirc;
  SMARTLIST_FOREACH_BEGIN(circuit_get_global_list(), circuit_t *, circ) {
    if (!CIRCUIT_IS_ORIGIN(circ))
      continue;
    ocirc = TO_ORIGIN_CIRCUIT(circ);
    ocirc->n_written_circ_bw = ocirc->n_read_circ_bw = 0;
    ocirc->n_overhead_written_circ_bw = ocirc->n_overhead_read_circ_bw = 0;
    ocirc->n_delivered_written_circ_bw = ocirc->n_delivered_read_circ_bw = 0;
  }
  SMARTLIST_FOREACH_END(circ);
}

/** Set <b>global_event_mask*</b> to the bitwise OR of each live control
 * connection's event_mask field. */
void
control_update_global_event_mask(void)
{
  smartlist_t *conns = get_connection_array();
  event_mask_t old_mask, new_mask;
  old_mask = global_event_mask;
  int any_old_per_sec_events = control_any_per_second_event_enabled();

  global_event_mask = 0;
  SMARTLIST_FOREACH(conns, connection_t *, _conn,
  {
    if (_conn->type == CONN_TYPE_CONTROL &&
        STATE_IS_OPEN(_conn->state)) {
      control_connection_t *conn = TO_CONTROL_CONN(_conn);
      global_event_mask |= conn->event_mask;
    }
  });

  new_mask = global_event_mask;

  /* Handle the aftermath.  Set up the log callback to tell us only what
   * we want to hear...*/
  control_adjust_event_log_severity();

  /* Macro: true if ev was false before and is true now. */
#define NEWLY_ENABLED(ev) \
  (! (old_mask & (ev)) && (new_mask & (ev)))

  /* ...then, if we've started logging stream or circ bw, clear the
   * appropriate fields. */
  if (NEWLY_ENABLED(EVENT_STREAM_BANDWIDTH_USED)) {
    SMARTLIST_FOREACH(conns, connection_t *, conn,
    {
      if (conn->type == CONN_TYPE_AP) {
        edge_connection_t *edge_conn = TO_EDGE_CONN(conn);
        edge_conn->n_written = edge_conn->n_read = 0;
      }
    });
  }
  if (NEWLY_ENABLED(EVENT_CIRC_BANDWIDTH_USED)) {
    clear_circ_bw_fields();
  }
  if (NEWLY_ENABLED(EVENT_BANDWIDTH_USED)) {
    uint64_t r, w;
    control_get_bytes_rw_last_sec(&r, &w);
  }
  if (any_old_per_sec_events != control_any_per_second_event_enabled()) {
    rescan_periodic_events(get_options());
  }

#undef NEWLY_ENABLED
}

/** Adjust the log severities that result in control_event_logmsg being called
 * to match the severity of log messages that any controllers are interested
 * in. */
void
control_adjust_event_log_severity(void)
{
  int i;
  int min_log_event=EVENT_ERR_MSG, max_log_event=EVENT_DEBUG_MSG;

  for (i = EVENT_DEBUG_MSG; i <= EVENT_ERR_MSG; ++i) {
    if (EVENT_IS_INTERESTING(i)) {
      min_log_event = i;
      break;
    }
  }
  for (i = EVENT_ERR_MSG; i >= EVENT_DEBUG_MSG; --i) {
    if (EVENT_IS_INTERESTING(i)) {
      max_log_event = i;
      break;
    }
  }
  if (EVENT_IS_INTERESTING(EVENT_STATUS_GENERAL)) {
    if (min_log_event > EVENT_NOTICE_MSG)
      min_log_event = EVENT_NOTICE_MSG;
    if (max_log_event < EVENT_ERR_MSG)
      max_log_event = EVENT_ERR_MSG;
  }
  if (min_log_event <= max_log_event)
    change_callback_log_severity(event_to_log_severity(min_log_event),
                                 event_to_log_severity(max_log_event),
                                 control_event_logmsg);
  else
    change_callback_log_severity(LOG_ERR, LOG_ERR,
                                 control_event_logmsg);
}

/** Return true iff the event with code <b>c</b> is being sent to any current
 * control connection.  This is useful if the amount of work needed to prepare
 * to call the appropriate control_event_...() function is high.
 */
int
control_event_is_interesting(int event)
{
  return EVENT_IS_INTERESTING(event);
}

/** Return true if any event that needs to fire once a second is enabled. */
int
control_any_per_second_event_enabled(void)
{
  return ANY_EVENT_IS_INTERESTING(
      EVENT_MASK_(EVENT_BANDWIDTH_USED) |
      EVENT_MASK_(EVENT_CELL_STATS) |
      EVENT_MASK_(EVENT_CIRC_BANDWIDTH_USED) |
      EVENT_MASK_(EVENT_CONN_BW) |
      EVENT_MASK_(EVENT_STREAM_BANDWIDTH_USED)
  );
}

/** Represents an event that's queued to be sent to one or more
 * controllers. */
typedef struct queued_event_s {
  uint16_t event;
  char *msg;
} queued_event_t;

/** Pointer to int. If this is greater than 0, we don't allow new events to be
 * queued. */
static tor_threadlocal_t block_event_queue_flag;

/** Holds a smartlist of queued_event_t objects that may need to be sent
 * to one or more controllers */
static smartlist_t *queued_control_events = NULL;

/** True if the flush_queued_events_event is pending. */
static int flush_queued_event_pending = 0;

/** Lock to protect the above fields. */
static tor_mutex_t *queued_control_events_lock = NULL;

/** An event that should fire in order to flush the contents of
 * queued_control_events. */
static mainloop_event_t *flush_queued_events_event = NULL;

void
control_initialize_event_queue(void)
{
  if (queued_control_events == NULL) {
    queued_control_events = smartlist_new();
  }

  if (flush_queued_events_event == NULL) {
    struct event_base *b = tor_libevent_get_base();
    if (b) {
      flush_queued_events_event =
        mainloop_event_new(flush_queued_events_cb, NULL);
      tor_assert(flush_queued_events_event);
    }
  }

  if (queued_control_events_lock == NULL) {
    queued_control_events_lock = tor_mutex_new();
    tor_threadlocal_init(&block_event_queue_flag);
  }
}

static int *
get_block_event_queue(void)
{
  int *val = tor_threadlocal_get(&block_event_queue_flag);
  if (PREDICT_UNLIKELY(val == NULL)) {
    val = tor_malloc_zero(sizeof(int));
    tor_threadlocal_set(&block_event_queue_flag, val);
  }
  return val;
}

/** Helper: inserts an event on the list of events queued to be sent to
 * one or more controllers, and schedules the events to be flushed if needed.
 *
 * This function takes ownership of <b>msg</b>, and may free it.
 *
 * We queue these events rather than send them immediately in order to break
 * the dependency in our callgraph from code that generates events for the
 * controller, and the network layer at large.  Otherwise, nearly every
 * interesting part of Tor would potentially call every other interesting part
 * of Tor.
 */
MOCK_IMPL(STATIC void,
queue_control_event_string,(uint16_t event, char *msg))
{
  /* This is redundant with checks done elsewhere, but it's a last-ditch
   * attempt to avoid queueing something we shouldn't have to queue. */
  if (PREDICT_UNLIKELY( ! EVENT_IS_INTERESTING(event) )) {
    tor_free(msg);
    return;
  }

  int *block_event_queue = get_block_event_queue();
  if (*block_event_queue) {
    tor_free(msg);
    return;
  }

  queued_event_t *ev = tor_malloc(sizeof(*ev));
  ev->event = event;
  ev->msg = msg;

  /* No queueing an event while queueing an event */
  ++*block_event_queue;

  tor_mutex_acquire(queued_control_events_lock);
  tor_assert(queued_control_events);
  smartlist_add(queued_control_events, ev);

  int activate_event = 0;
  if (! flush_queued_event_pending && in_main_thread()) {
    activate_event = 1;
    flush_queued_event_pending = 1;
  }

  tor_mutex_release(queued_control_events_lock);

  --*block_event_queue;

  /* We just put an event on the queue; mark the queue to be
   * flushed.  We only do this from the main thread for now; otherwise,
   * we'd need to incur locking overhead in Libevent or use a socket.
   */
  if (activate_event) {
    tor_assert(flush_queued_events_event);
    mainloop_event_activate(flush_queued_events_event);
  }
}

#define queued_event_free(ev) \
  FREE_AND_NULL(queued_event_t, queued_event_free_, (ev))

/** Release all storage held by <b>ev</b>. */
static void
queued_event_free_(queued_event_t *ev)
{
  if (ev == NULL)
    return;

  tor_free(ev->msg);
  tor_free(ev);
}

/** Send every queued event to every controller that's interested in it,
 * and remove the events from the queue.  If <b>force</b> is true,
 * then make all controllers send their data out immediately, since we
 * may be about to shut down. */
static void
queued_events_flush_all(int force)
{
  /* Make sure that we get all the pending log events, if there are any. */
  flush_pending_log_callbacks();

  if (PREDICT_UNLIKELY(queued_control_events == NULL)) {
    return;
  }
  smartlist_t *all_conns = get_connection_array();
  smartlist_t *controllers = smartlist_new();
  smartlist_t *queued_events;

  int *block_event_queue = get_block_event_queue();
  ++*block_event_queue;

  tor_mutex_acquire(queued_control_events_lock);
  /* No queueing an event while flushing events. */
  flush_queued_event_pending = 0;
  queued_events = queued_control_events;
  queued_control_events = smartlist_new();
  tor_mutex_release(queued_control_events_lock);

  /* Gather all the controllers that will care... */
  SMARTLIST_FOREACH_BEGIN(all_conns, connection_t *, conn) {
    if (conn->type == CONN_TYPE_CONTROL &&
        !conn->marked_for_close &&
        conn->state == CONTROL_CONN_STATE_OPEN) {
      control_connection_t *control_conn = TO_CONTROL_CONN(conn);

      smartlist_add(controllers, control_conn);
    }
  } SMARTLIST_FOREACH_END(conn);

  SMARTLIST_FOREACH_BEGIN(queued_events, queued_event_t *, ev) {
    const event_mask_t bit = ((event_mask_t)1) << ev->event;
    const size_t msg_len = strlen(ev->msg);
    SMARTLIST_FOREACH_BEGIN(controllers, control_connection_t *,
                            control_conn) {
      if (control_conn->event_mask & bit) {
        connection_buf_add(ev->msg, msg_len, TO_CONN(control_conn));
      }
    } SMARTLIST_FOREACH_END(control_conn);

    queued_event_free(ev);
  } SMARTLIST_FOREACH_END(ev);

  if (force) {
    SMARTLIST_FOREACH_BEGIN(controllers, control_connection_t *,
                            control_conn) {
      connection_flush(TO_CONN(control_conn));
    } SMARTLIST_FOREACH_END(control_conn);
  }

  smartlist_free(queued_events);
  smartlist_free(controllers);

  --*block_event_queue;
}

/** Libevent callback: Flushes pending events to controllers that are
 * interested in them. */
static void
flush_queued_events_cb(mainloop_event_t *event, void *arg)
{
  (void) event;
  (void) arg;
  queued_events_flush_all(0);
}

/** Send an event to all v1 controllers that are listening for code
 * <b>event</b>.  The event's body is given by <b>msg</b>.
 *
 * The EXTENDED_FORMAT and NONEXTENDED_FORMAT flags behave similarly with
 * respect to the EXTENDED_EVENTS feature. */
MOCK_IMPL(STATIC void,
send_control_event_string,(uint16_t event,
                           const char *msg))
{
  tor_assert(event >= EVENT_MIN_ && event <= EVENT_MAX_);
  queue_control_event_string(event, tor_strdup(msg));
}

/** Helper for send_control_event and control_event_status:
 * Send an event to all v1 controllers that are listening for code
 * <b>event</b>.  The event's body is created by the printf-style format in
 * <b>format</b>, and other arguments as provided. */
static void
send_control_event_impl(uint16_t event,
                        const char *format, va_list ap)
{
  char *buf = NULL;
  int len;

  len = tor_vasprintf(&buf, format, ap);
  if (len < 0) {
    log_warn(LD_BUG, "Unable to format event for controller.");
    return;
  }

  queue_control_event_string(event, buf);
}

/** Send an event to all v1 controllers that are listening for code
 * <b>event</b>.  The event's body is created by the printf-style format in
 * <b>format</b>, and other arguments as provided. */
static void
send_control_event(uint16_t event,
                   const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  send_control_event_impl(event, format, ap);
  va_end(ap);
}

#ifdef TOR_UNIT_TESTS
/* For testing: change the value of global_event_mask */
void
control_testing_set_global_event_mask(uint64_t mask)
{
  global_event_mask = mask;
}
#endif /* defined(TOR_UNIT_TESTS) */

/**
 * Logging callback: called when there is a queued pending log callback.
 */
void
control_event_logmsg_pending(void)
{
  if (! in_main_thread()) {
    /* We can't handle this case yet, since we're using a
     * mainloop_event_t to invoke queued_events_flush_all.  We ought to
     * use a different mechanism instead: see #25987.
     **/
    return;
  }
  tor_assert(flush_queued_events_event);
  mainloop_event_activate(flush_queued_events_event);
}

/** Helper structure: maps event values to their names. */
struct control_event_t {
  uint16_t event_code;
  const char *event_name;
};
/** Table mapping event values to their names.  Used to implement SETEVENTS
 * and GETINFO events/names, and to keep they in sync. */
static const struct control_event_t control_event_table[] = {
  { EVENT_CIRCUIT_STATUS, "CIRC" },
  { EVENT_CIRCUIT_STATUS_MINOR, "CIRC_MINOR" },
  { EVENT_STREAM_STATUS, "STREAM" },
  { EVENT_OR_CONN_STATUS, "ORCONN" },
  { EVENT_BANDWIDTH_USED, "BW" },
  { EVENT_DEBUG_MSG, "DEBUG" },
  { EVENT_INFO_MSG, "INFO" },
  { EVENT_NOTICE_MSG, "NOTICE" },
  { EVENT_WARN_MSG, "WARN" },
  { EVENT_ERR_MSG, "ERR" },
  { EVENT_NEW_DESC, "NEWDESC" },
  { EVENT_ADDRMAP, "ADDRMAP" },
  { EVENT_DESCCHANGED, "DESCCHANGED" },
  { EVENT_NS, "NS" },
  { EVENT_STATUS_GENERAL, "STATUS_GENERAL" },
  { EVENT_STATUS_CLIENT, "STATUS_CLIENT" },
  { EVENT_STATUS_SERVER, "STATUS_SERVER" },
  { EVENT_GUARD, "GUARD" },
  { EVENT_STREAM_BANDWIDTH_USED, "STREAM_BW" },
  { EVENT_CLIENTS_SEEN, "CLIENTS_SEEN" },
  { EVENT_NEWCONSENSUS, "NEWCONSENSUS" },
  { EVENT_BUILDTIMEOUT_SET, "BUILDTIMEOUT_SET" },
  { EVENT_GOT_SIGNAL, "SIGNAL" },
  { EVENT_CONF_CHANGED, "CONF_CHANGED"},
  { EVENT_CONN_BW, "CONN_BW" },
  { EVENT_CELL_STATS, "CELL_STATS" },
  { EVENT_CIRC_BANDWIDTH_USED, "CIRC_BW" },
  { EVENT_TRANSPORT_LAUNCHED, "TRANSPORT_LAUNCHED" },
  { EVENT_HS_DESC, "HS_DESC" },
  { EVENT_HS_DESC_CONTENT, "HS_DESC_CONTENT" },
  { EVENT_NETWORK_LIVENESS, "NETWORK_LIVENESS" },
  { 0, NULL },
};

/** Called when we get a SETEVENTS message: update conn->event_mask,
 * and reply with DONE or ERROR. */
int
handle_control_setevents(control_connection_t *conn, uint32_t len,
                         const char *body)
{
  int event_code;
  event_mask_t event_mask = 0;
  smartlist_t *events = smartlist_new();

  (void) len;

  smartlist_split_string(events, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH_BEGIN(events, const char *, ev)
    {
      if (!strcasecmp(ev, "EXTENDED") ||
          !strcasecmp(ev, "AUTHDIR_NEWDESCS")) {
        log_warn(LD_CONTROL, "The \"%s\" SETEVENTS argument is no longer "
                 "supported.", ev);
        continue;
      } else {
        int i;
        event_code = -1;

        for (i = 0; control_event_table[i].event_name != NULL; ++i) {
          if (!strcasecmp(ev, control_event_table[i].event_name)) {
            event_code = control_event_table[i].event_code;
            break;
          }
        }

        if (event_code == -1) {
          connection_printf_to_buf(conn, "552 Unrecognized event \"%s\"\r\n",
                                   ev);
          SMARTLIST_FOREACH(events, char *, e, tor_free(e));
          smartlist_free(events);
          return 0;
        }
      }
      event_mask |= (((event_mask_t)1) << event_code);
    }
  SMARTLIST_FOREACH_END(ev);
  SMARTLIST_FOREACH(events, char *, e, tor_free(e));
  smartlist_free(events);

  conn->event_mask = event_mask;

  control_update_global_event_mask();
  send_control_done(conn);
  return 0;
}

char *
getinfo_events(void)
{
    int i;
    smartlist_t *event_names = smartlist_new();

    for (i = 0; control_event_table[i].event_name != NULL; ++i) {
      smartlist_add(event_names, (char *)control_event_table[i].event_name);
    }

    *answer = smartlist_join_strings(event_names, " ", 0, NULL);

    smartlist_free(event_names);
}

void
control_events_free_all(void)
{
  smartlist_t *queued_events = NULL;

  if (queued_control_events_lock) {
    tor_mutex_acquire(queued_control_events_lock);
    flush_queued_event_pending = 0;
    queued_events = queued_control_events;
    queued_control_events = NULL;
    tor_mutex_release(queued_control_events_lock);
  }
  if (queued_events) {
    SMARTLIST_FOREACH(queued_events, queued_event_t *, ev,
                      queued_event_free(ev));
    smartlist_free(queued_events);
  }
  if (flush_queued_events_event) {
    mainloop_event_free(flush_queued_events_event);
    flush_queued_events_event = NULL;
  }
  global_event_mask = 0;
}
