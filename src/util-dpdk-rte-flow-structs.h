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
 * DPDK rte_flow rules util structures
 *
 */

#ifndef SURICATA_RTE_FLOW_STRUCTS_H
#define SURICATA_RTE_FLOW_STRUCTS_H

#ifdef HAVE_DPDK
#include "suricata-common.h"
#include "util-dpdk-common.h"

#define RTE_PATTERN_TEMPLATES_MAX_CNT 4
#define RTE_PATTERN_TEMPLATE_DEFAULT 0
#define RTE_ACTIONS_TEMPLATE_DEFAULT 0

enum RteTemplatePatterns {
    RTE_PATTERN_TEMPLATE_TCP_VLAN,
    RTE_PATTERN_TEMPLATE_TCP_NO_VLAN,
    RTE_PATTERN_TEMPLATE_UDP_VLAN,
    RTE_PATTERN_TEMPLATE_UDP_NO_VLAN
};

enum RteItemsOrder {
    L2_INDEX = 0,
    VLAN_INDEX,
    L3_INDEX,
    L4_INDEX,
    END_INDEX
};

typedef struct Packet_ Packet;
typedef struct Flow_ Flow;
typedef struct RteFlowBypassData_ RteFlowBypassData;

typedef struct RteFlowTemplateResources_ {
    struct rte_flow_template_table *tbl;
    struct rte_flow_pattern_template *pt[RTE_PATTERN_TEMPLATES_MAX_CNT];
    struct rte_flow_actions_template *at;
    uint16_t pt_cnt; 
} RteFlowTemplateResources;

typedef struct RteFlowHandlerToFlow_ {
    Flow *flow;
    struct rte_flow *src_handle;
    struct rte_flow *dst_handle;
    struct rte_flow_action_handle *src_action_handle;
    struct rte_flow_action_handle *dst_action_handle;
    struct rte_flow_action_list_handle *src_action_list_handle;
    struct rte_flow_action_list_handle *dst_action_list_handle;
    RteFlowBypassData *rte_flow_bypass_data;
    uint16_t livedev_id;
    uint16_t in_queue_id;
    bool is_final;
    void *query[3];
    struct rte_flow_item_conntrack conntrack;
	struct rte_flow_query_count count_src;
	struct rte_flow_query_count count_dst;
} RteFlowHandlerToFlow;

typedef struct RteFlowBypassData_ {
    struct rte_mempool *bypass_info_mp;
    struct rte_mempool *bypass_mp;
    struct rte_ring *bypass_ring;
    uint32_t rte_bypass_rule_capacity;
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_rules_created);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_rules_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_rules_active);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_rules_unchecked);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_flows_bypass_success);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_flows_bypass_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_flow_lookup_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_mempool_key_get_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_mempool_info_get_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_query_error);
    /* Aggregate packet/byte counters of all bypassed flows. These feed the
     * flow_bypassed.packets / flow_bypassed.bytes stats via RteFlowCheckRules. */
    SC_ATOMIC_DECLARE(uint64_t, rte_bypass_pkts);
    SC_ATOMIC_DECLARE(uint64_t, rte_bypass_bytes);
    RteFlowTemplateResources *rss_resources;
    RteFlowTemplateResources *jump_resources;
    RteFlowTemplateResources *bypass_resources_ipv4;
    RteFlowTemplateResources *bypass_resources_ipv6;
    uint16_t port_id;
    uint16_t nb_rx_queues;
    int (*RteFlowDeviceBypassCallback)(Packet *p);
    int (*RteFlowDeviceBypassUpdateStats)(uint16_t queue_id, RteFlowHandlerToFlow *flow_handler_info);
    void (*RteFlowDeviceDestroyRule)(uint16_t queue_id, RteFlowHandlerToFlow *flow_handler_info);
    int (*RteFlowDeviceTemplatesInit)(uint16_t port_id, uint16_t queues_nb, const char *port_name, RteFlowBypassData *rte_flow_bypass_data);
    int (*RteFlowDeviceCreateIndirectAction)(uint16_t port_id, RteFlowHandlerToFlow *flow_handler_info);
    uint16_t rte_flow_manager_queue_base;
    uint32_t nb_flow_manager_queues;
    // TODO change value
    char drive_name[30];
} RteFlowBypassData;

/** \brief Holds RSS Template API resources for cleanup on device close */
typedef struct RteFlowRSSTemplateResources_ {
    struct rte_flow_template_table *tbl;
    struct rte_flow_pattern_template *pt;
    struct rte_flow_actions_template *at;
} RteFlowRSSTemplateResources;

static const struct rte_flow_item pattern_template_novlan_ipv4_tcp[] = {
	{ .type = RTE_FLOW_ITEM_TYPE_ETH },
	{ .type = RTE_FLOW_ITEM_TYPE_VOID }, // NOTE: This is here just for convinience
	{ .type = RTE_FLOW_ITEM_TYPE_IPV4, .mask = &rte_flow_item_ipv4_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_TCP,  .mask = &rte_flow_item_tcp_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_END },
};

static const struct rte_flow_item pattern_template_novlan_ipv4_udp[] = {
	{ .type = RTE_FLOW_ITEM_TYPE_ETH },
	{ .type = RTE_FLOW_ITEM_TYPE_VOID }, // NOTE: This is here just for convinience
	{ .type = RTE_FLOW_ITEM_TYPE_IPV4, .mask = &rte_flow_item_ipv4_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_UDP,  .mask = &rte_flow_item_udp_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_END },
};

static const struct rte_flow_item pattern_template_novlan_ipv6_tcp[] = {
	{ .type = RTE_FLOW_ITEM_TYPE_ETH },
	{ .type = RTE_FLOW_ITEM_TYPE_VOID }, // NOTE: This is here just for convinience
	{ .type = RTE_FLOW_ITEM_TYPE_IPV6, .mask = &rte_flow_item_ipv6_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_TCP,  .mask = &rte_flow_item_tcp_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_END },
};

static const struct rte_flow_item pattern_template_novlan_ipv6_udp[] = {
	{ .type = RTE_FLOW_ITEM_TYPE_ETH },
	{ .type = RTE_FLOW_ITEM_TYPE_VOID }, // NOTE: This is here just for convinience
	{ .type = RTE_FLOW_ITEM_TYPE_IPV6, .mask = &rte_flow_item_ipv6_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_UDP,  .mask = &rte_flow_item_udp_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_END },
};

static const struct rte_flow_item pattern_template_vlan_ipv4_tcp[] = {
	{ .type = RTE_FLOW_ITEM_TYPE_ETH },
	{ .type = RTE_FLOW_ITEM_TYPE_VLAN, .mask = &rte_flow_item_vlan_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_IPV4, .mask = &rte_flow_item_ipv4_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_TCP,  .mask = &rte_flow_item_tcp_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_END },
};

static const struct rte_flow_item pattern_template_vlan_ipv4_udp[] = {
	{ .type = RTE_FLOW_ITEM_TYPE_ETH },
	{ .type = RTE_FLOW_ITEM_TYPE_VLAN, .mask = &rte_flow_item_vlan_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_IPV4, .mask = &rte_flow_item_ipv4_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_UDP,  .mask = &rte_flow_item_udp_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_END },
};

static const struct rte_flow_item pattern_template_vlan_ipv6_tcp[] = {
	{ .type = RTE_FLOW_ITEM_TYPE_ETH },
	{ .type = RTE_FLOW_ITEM_TYPE_VLAN, .mask = &rte_flow_item_vlan_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_IPV6, .mask = &rte_flow_item_ipv6_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_TCP,  .mask = &rte_flow_item_tcp_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_END },
};

static const struct rte_flow_item pattern_template_vlan_ipv6_udp[] = {
	{ .type = RTE_FLOW_ITEM_TYPE_ETH },
	{ .type = RTE_FLOW_ITEM_TYPE_VLAN, .mask = &rte_flow_item_vlan_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_IPV6, .mask = &rte_flow_item_ipv6_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_UDP,  .mask = &rte_flow_item_udp_mask },
	{ .type = RTE_FLOW_ITEM_TYPE_END },
};

#endif /* HAVE_DPDK */
#endif /* SURICATA_RTE_FLOW_STRUCTS_H */
/**
 * @}
 */
