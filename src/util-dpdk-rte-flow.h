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
 *  \defgroup dpdk DPDK rte_flow rules util functions
 *
 *  @{
 */

/**
 * \file
 *
 * \author Adam Kiripolsky <adam.kiripolsky@cesnet.cz>
 *
 * DPDK rte_flow rules util functions
 *
 */

#ifndef SURICATA_RTE_FLOW_RULES_H
#define SURICATA_RTE_FLOW_RULES_H

#ifdef HAVE_DPDK

#include "conf.h"
#include "flow-bypass.h"
#include "flow-hash.h"
#include "util-dpdk-common.h"
#include "util-dpdk-rte-flow-structs.h"

int ConfigSetCaptureBypass(DPDKIfaceConfig *);
int RteBypassInit(DPDKIfaceConfig *iconf, const char *driver_name);
int RteFlowBypassCallback(Packet *);
bool RteBypassUpdate(Flow *flow, void *data, time_t tsec);
void RteBypassFree(void *data);
int RteFlowCreateJumpRule(uint16_t, const char *, RteFlowBypassData *rte_flow_bypass_data);
void RteFlowSetFlowBypassInfo(FlowBypassInfo *fc,
        Flow *flow, struct rte_flow *src_handler, struct rte_flow *dst_handler, struct rte_flow_action_list_handle *src_action_list_handle, struct rte_flow_action_list_handle *dst_action_list_handle, int family);
/* Template API resource management */
struct rte_flow *RteFlowCreateRuleAsync(int port_id, uint32_t queue_id, struct rte_flow_template_table *table,
				  struct rte_flow_item *pattern, uint8_t pt_index, struct rte_flow_action *actions, uint8_t at_index, void *user_data);
int RteFlowBypassTemplateResourcesInit(uint16_t port_id, RteFlowBypassData *data);
void RteFlowBypasTemplateResourcesFree(uint16_t port_id, RteFlowTemplateResources *template_resources);
enum RteTemplatePatterns RteGetTemplatePatternIndex(bool has_vlan, bool is_tcp);

/* Template creation helpers */
int RteFlowJumpRuleTemplateInit(uint16_t port_id, RteFlowBypassData *rte_flow_bypass_data);
void RteFlowActionHandleDestroyFlow(RteFlowBypassData *rte_flow_bypass_data,
        uint16_t port_id, struct rte_flow_action_handle *action_handle);
struct rte_flow_pattern_template *
RteFlowCreatePatternTemplate(int, const struct rte_flow_item *);
struct rte_flow_actions_template *
RteFlowCreateActionTemplate(int, struct rte_flow_action *,
        struct rte_flow_action *);
struct rte_flow_template_table *
RteFlowCreateTemplateTable(int, uint32_t, uint32_t, uint32_t,
        struct rte_flow_pattern_template **, uint32_t,
        struct rte_flow_actions_template **, uint32_t);

#endif /* HAVE_DPDK */
#endif /* SURICATA_RTE_FLOW_RULES_H */
/**
 * @}
 */
