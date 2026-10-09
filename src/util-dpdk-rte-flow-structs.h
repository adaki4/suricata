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

typedef struct FlowKey_ FlowKey;
typedef struct RteFlowRuleStorage_ {
    uint32_t rule_cnt;
    uint32_t rule_size;
    char **rules;
    struct rte_flow **rule_handlers;
} RteFlowRuleStorage;

/* Maximum number of distinct physical NICs the bypass can account for. */
#define RTE_BYPASS_MAX_NICS 16

/**
 * \brief rte_flow rule accounting for one physical NIC.
 *
 * mlx5 devices share the rte_flow rule space per physical device (E-Switch),
 * not per interface/port. Each physical NIC therefore tracks its own rule
 * budget (capacity) and the number of rules currently installed on it,
 * independently of the other NICs.
 */
typedef struct RteFlowNicBudget_ {
    uint32_t nic_key;       /* identity of the physical NIC (switch domain id) */
    uint32_t rule_capacity; /* driver rte_flow rule capacity of the device */
    SC_ATOMIC_DECLARE(uint32_t, rules_active);  /* rules currently installed on the NIC */
    SC_ATOMIC_DECLARE(uint32_t, rules_created); /* cumulative rules created on the NIC */
    SC_ATOMIC_DECLARE(uint32_t, rules_error);   /* rule creation errors on the NIC */
} RteFlowNicBudget;

/**
 * \brief Shared rte_flow bypass state.
 *
 * One instance for the whole bypass: a single ring and FlowKey mempool is
 * used to hand flows from workers to the bypass manager, and a single
 * bypass-info mempool stores the per-flow rule handlers for all NICs. Rule
 * capacity is enforced per physical NIC through the nic_budgets array.
 */
typedef struct RteFlowBypassData_ {
    struct rte_mempool *bypass_info_mp;
    struct rte_mempool *bypass_mp;
    struct rte_ring *bypass_ring;
    uint32_t rte_ring_dequeue_burst_size;
    FlowKey **ring_dequeue_buffer;
    /* ID of livedev that updates shared stats in DPDKDumpCounters() */
    uint32_t counter_update_livedev_id;
    /* Summed driver rule capacity of all registered NICs (used to size
     * bypass_info_mp when not user-configured). */
    uint32_t total_rule_capacity;
    /* Per-physical-NIC rule budgets. */
    RteFlowNicBudget nic_budgets[RTE_BYPASS_MAX_NICS];
    uint32_t nic_cnt;
    SC_ATOMIC_DECLARE(uint32_t, ref_cnt);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_rules_query_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_ring_enqueue_success);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_ring_enqueue_error_ring_full);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_ring_dequeue_success);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_ring_max);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_ring_occupancy);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_ring_ops);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_flows_bypass_success);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_flows_bypass_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_flows_lookup_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_mempool_key_get_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_mempool_info_get_error);
} RteFlowBypassData;

#endif /* HAVE_DPDK */
#endif /* SURICATA_RTE_FLOW_STRUCTS_H */
/**
 * @}
 */
