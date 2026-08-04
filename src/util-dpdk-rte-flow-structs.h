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

#define RTE_PATTERN_TEMPLATES_MAX_CNT 2
#define RTE_PATTERN_TEMPLATE_DEFAULT 0
#define RTE_PATTERN_TEMPLATE_TCP 0
#define RTE_PATTERN_TEMPLATE_UDP 1

#define RTE_ACTIONS_TEMPLATE_DEFAULT 0

typedef struct RteFlowTemplateResources_ {
    struct rte_flow_template_table *tbl;
    struct rte_flow_pattern_template *pt[RTE_PATTERN_TEMPLATES_MAX_CNT];
    uint16_t pt_cnt; 
    struct rte_flow_actions_template *at;
} RteFlowTemplateResources;

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
    RteFlowTemplateResources *rss_resources;
    RteFlowTemplateResources *jump_resources;
    RteFlowTemplateResources *bypass_resources_ipv4;
    RteFlowTemplateResources *bypass_resources_ipv6;
    uint16_t port_id;

} RteFlowBypassData;

/** \brief Holds RSS Template API resources for cleanup on device close */
typedef struct RteFlowRSSTemplateResources_ {
    struct rte_flow_template_table *tbl;
    struct rte_flow_pattern_template *pt;
    struct rte_flow_actions_template *at;
} RteFlowRSSTemplateResources;

#endif /* HAVE_DPDK */
#endif /* SURICATA_RTE_FLOW_STRUCTS_H */
/**
 * @}
 */
