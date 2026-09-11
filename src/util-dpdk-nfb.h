/* Copyright (C) 2025 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Adam Kiripolsky <adam.kiripolsky@cesnet.cz>
 */

#ifndef UTIL_DPDK_NFB_H
#define UTIL_DPDK_NFB_H

#include "suricata-common.h"
#include "util-dpdk-rte-flow-structs.h"

#ifdef HAVE_DPDK

typedef struct DPDKIfaceConfig_ DPDKIfaceConfig;
typedef struct LiveDevice_ LiveDevice;

#define NFB_RTE_FLOW_RULES_CAPACITY 4194304

void nfbDeviceSetRSSConf(struct rte_eth_rss_conf *rss_conf);
int nfbDevicePostStartActions(int port_id, uint16_t nb_rx_queues, char *port_name, bool capture_bypass_enabled, RteFlowBypassData *rte_flow_bypass_data);
int nfbDeviceRteFlowTemplatesInit(uint16_t port_id, uint16_t queues_nb, const char *port_name, RteFlowBypassData *rte_flow_bypass_data);
int nfbDeviceRteFlowUpdateStats(uint16_t queue_id, RteFlowHandlerToFlow *flow_handler_info);
int nfbDeviceRteFlowBypassCallback(Packet *p);
void nfbDeviceRteFlowRuleDestroy(uint16_t queue_id, RteFlowHandlerToFlow *flow_handler_info);

#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_NFB_H */
