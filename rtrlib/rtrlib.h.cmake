/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#ifndef RTRLIB_H
#define RTRLIB_H

#cmakedefine RTRLIB_HAVE_LIBSSH
#define RTRLIB_VERSION_MAJOR @RTRLIB_VERSION_MAJOR@
#define RTRLIB_VERSION_MINOR @RTRLIB_VERSION_MINOR@
#define RTRLIB_VERSION_PATCH @RTRLIB_VERSION_PATCH@

#include "lib/alloc_utils_public.h"
#include "lib/ip_public.h"
#include "lib/ipv4_public.h"
#include "lib/ipv6_public.h"
#include "pfx/pfx_public.h"
#include "rtr/rtr_public.h"
#include "rtr_mgr_public.h"
#include "spki/spkitable_public.h"
#include "transport/tcp/tcp_transport_public.h"
#include "transport/transport_public.h"
#ifdef RTRLIB_HAVE_LIBSSH
#include "rtrlib/transport/ssh/ssh_transport_public.h"
#endif

#endif
