/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control_event.h
 * \brief Header file for control_event.c.
 **/

#ifndef TOR_CONTROL_EVENT_H
#define TOR_CONTROL_EVENT_H

/* Recognized asynchronous event types.  It's okay to expand this list
 * because it is used both as a list of v0 event types, and as indices
 * into the bitfield to determine which controllers want which events.
 */
/* This bitfield has no event zero    0x0000 */
#define EVENT_MIN_                    0x0001
#define EVENT_CIRCUIT_STATUS          0x0001
#define EVENT_STREAM_STATUS           0x0002
#define EVENT_OR_CONN_STATUS          0x0003
#define EVENT_BANDWIDTH_USED          0x0004
#define EVENT_CIRCUIT_STATUS_MINOR    0x0005
#define EVENT_NEW_DESC                0x0006
#define EVENT_DEBUG_MSG               0x0007
#define EVENT_INFO_MSG                0x0008
#define EVENT_NOTICE_MSG              0x0009
#define EVENT_WARN_MSG                0x000A
#define EVENT_ERR_MSG                 0x000B
#define EVENT_ADDRMAP                 0x000C
/* There was an AUTHDIR_NEWDESCS event, but it no longer exists.  We
   can reclaim 0x000D. */
#define EVENT_DESCCHANGED             0x000E
/* Previously exposed in control.h. */
#define EVENT_NS                      0x000F
#define EVENT_STATUS_CLIENT           0x0010
#define EVENT_STATUS_SERVER           0x0011
#define EVENT_STATUS_GENERAL          0x0012
#define EVENT_GUARD                   0x0013
#define EVENT_STREAM_BANDWIDTH_USED   0x0014
#define EVENT_CLIENTS_SEEN            0x0015
#define EVENT_NEWCONSENSUS            0x0016
#define EVENT_BUILDTIMEOUT_SET        0x0017
#define EVENT_GOT_SIGNAL              0x0018
#define EVENT_CONF_CHANGED            0x0019
#define EVENT_CONN_BW                 0x001A
#define EVENT_CELL_STATS              0x001B
/* UNUSED :                           0x001C */
#define EVENT_CIRC_BANDWIDTH_USED     0x001D
#define EVENT_TRANSPORT_LAUNCHED      0x0020
#define EVENT_HS_DESC                 0x0021
#define EVENT_HS_DESC_CONTENT         0x0022
#define EVENT_NETWORK_LIVENESS        0x0023
#define EVENT_MAX_                    0x0023

/* sizeof(control_connection_t.event_mask) in bits, currently a uint64_t */
#define EVENT_CAPACITY_               0x0040

/* If EVENT_MAX_ ever hits 0x0040, we need to make the mask into a
 * different structure, as it can only handle a maximum left shift of 1<<63. */

#if EVENT_MAX_ >= EVENT_CAPACITY_
#error control_connection_t.event_mask has an event greater than its capacity
#endif

#define EVENT_MASK_(e)               (((uint64_t)1)<<(e))

#define EVENT_MASK_NONE_             ((uint64_t)0x0)

#define EVENT_MASK_ABOVE_MIN_        ((~((uint64_t)0x0)) << EVENT_MIN_)
#define EVENT_MASK_BELOW_MAX_        ((~((uint64_t)0x0)) \
                                      >> (EVENT_CAPACITY_ - EVENT_MAX_ \
                                          - EVENT_MIN_))

#define EVENT_MASK_ALL_              (EVENT_MASK_ABOVE_MIN_ \
                                      & EVENT_MASK_BELOW_MAX_)

/** Given a control event code for a message event, return the corresponding
 * log severity. */
static inline int
event_to_log_severity(int event)
{
  switch (event) {
    case EVENT_DEBUG_MSG: return LOG_DEBUG;
    case EVENT_INFO_MSG: return LOG_INFO;
    case EVENT_NOTICE_MSG: return LOG_NOTICE;
    case EVENT_WARN_MSG: return LOG_WARN;
    case EVENT_ERR_MSG: return LOG_ERR;
    default: return -1;
  }
}

/** Given a log severity, return the corresponding control event code. */
static inline int
log_severity_to_event(int severity)
{
  switch (severity) {
    case LOG_DEBUG: return EVENT_DEBUG_MSG;
    case LOG_INFO: return EVENT_INFO_MSG;
    case LOG_NOTICE: return EVENT_NOTICE_MSG;
    case LOG_WARN: return EVENT_WARN_MSG;
    case LOG_ERR: return EVENT_ERR_MSG;
    default: return -1;
  }
}

#endif  /* defined(TOR_CONTROL_EVENT_H) */
