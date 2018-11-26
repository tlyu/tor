/* Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "core/or/or.h"
#include "lib/subsys/subsys.h"

#include "core/or/connection_or.h"
#include "core/or/orconn_state.h"
#include "core/or/orconn_sys.h"

static smartlist_t *orconn_state_rcvrs;

static int
orconn_state_init(void)
{
  orconn_state_rcvrs = smartlist_new();
  return 0;
}

static void
orconn_state_fini(void)
{
  smartlist_free(orconn_state_rcvrs);
}

void
orconn_state_subscribe(orconn_state_rcvr fn)
{
  /* Don't duplicate subscriptions. */
  if (smartlist_contains(orconn_state_rcvrs, fn))
    return;

  smartlist_add(orconn_state_rcvrs, fn);
}

void
orconn_state_publish(orconn_state_msg *msg)
{
  SMARTLIST_FOREACH_BEGIN(orconn_state_rcvrs, orconn_state_rcvr, fn) {
    if (!fn)
      continue;
    (*fn)(msg);
  } SMARTLIST_FOREACH_END(fn);
}

const subsys_fns_t sys_orconn = {
  .name = "orconn",
  .supported = true,
  .level = -40,
  .initialize = orconn_state_init,
  .shutdown = orconn_state_fini,
};
