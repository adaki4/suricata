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

#ifndef UTIL_DPDK_MLX5_H
#define UTIL_DPDK_MLX5_H

#include "suricata-common.h"
#include "util-dpdk-rte-flow-structs.h"

#ifdef HAVE_DPDK

typedef struct DPDKIfaceConfig_ DPDKIfaceConfig;

#define MLX5_RTE_FLOW_RULES_CAPACITY 4194304

int mlx5DeviceRteFlowTemplatesInit(uint16_t port_id, uint16_t queues_nb, const char *port_name, RteFlowBypassData *rte_flow_bypass_data) ;
int mlx5DevicePostStartActions(int port_id, uint16_t nb_rx_queues, char *port_name, bool capture_bypass_enabled, RteFlowBypassData *rte_flow_bypass_data);
int mlx5DeviceRteFlowUpdateStats(uint16_t queue_id, RteFlowHandlerToFlow *flow_handler_info);
struct rte_flow_action_list_handle *mlx5DeviceRteFlowCreateIndirectAction(uint16_t port_id, uint32_t queue_id, RteFlowHandlerToFlow *flow_handler_info);
void mlx5DeviceRteFlowRuleDestroy(uint16_t queue_id, RteFlowHandlerToFlow *flow_handler_info);
int mlx5DeviceRteFlowBypassCallback(Packet *p);

#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_MLX5_H */
