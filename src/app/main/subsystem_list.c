/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "app/main/subsysmgr.h"
#include "lib/cc/compat_compiler.h"
#include "lib/cc/torint.h"

#include "core/or/orconn_sys.h"
#include "lib/compress/compress_sys.h"
#include "lib/crypt_ops/crypto_sys.h"
#include "lib/err/torerr_sys.h"
#include "lib/log/log_sys.h"
#include "lib/net/network_sys.h"
#include "lib/process/winprocess_sys.h"
#include "lib/thread/thread_sys.h"
#include "lib/time/time_sys.h"
#include "lib/tls/tortls_sys.h"
#include "lib/wallclock/wallclock_sys.h"

#include <stddef.h>

/**
 * Global list of the subsystems in Tor, in the order of their initialization.
 **/
const subsys_fns_t *tor_subsystems[] = {
  &sys_winprocess, /* -100 */
  &sys_torerr, /* -100 */
  &sys_wallclock, /* -99 */
  &sys_threads, /* -95 */
  &sys_logging, /* -90 */
  &sys_time, /* -90 */
  &sys_network, /* -90 */
  &sys_compress, /* -70 */
  &sys_crypto, /* -60 */
  &sys_tortls, /* -50 */
  &sys_orconn, /* -40 */
};

const unsigned n_tor_subsystems = ARRAY_LENGTH(tor_subsystems);
