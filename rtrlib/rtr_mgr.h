/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#ifndef RTR_MGR
#define RTR_MGR
#include "rtrlib/rtr_mgr_public.h"
#include "rtrlib/spki/hashtable/tommyds-1.8/tommytypes.h"

//TODO Find a nicer way todo a linked list (without writing our own)
struct rtr_mgr_group_node {
	tommy_node node;
	struct rtr_mgr_group *group;
};

#endif
