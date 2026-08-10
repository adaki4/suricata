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

#include "decode.h"
#include "flow-bypass.h"
#include "flow-hash.h"
#include "flow-storage.h"
#include "flow-callbacks.h"
#include "runmode-dpdk.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-ice.h"
#include "util-dpdk-mlx5.h"
#include "util-dpdk-rte-flow.h"
#include "util-dpdk-rte-flow-pattern.h"
#include "util-device-private.h"
#include "flow-private.h"
#include "flow.h"
#include "runmodes.h"
#include "tm-threads.h"
#include "suricata.h"

#ifdef HAVE_DPDK

#define COUNT_ACTION_ID        1

#define RTE_BYPASS_RING_NAME         "rte_bypass_ring"
#define RTE_BYPASS_MEMPOOL_NAME      "rte_bypass_mempool"
#define RTE_BYPASS_INFO_MEMPOOL_NAME "rte_bypass_info_mempool"
#define RTE_BYPASS_RING_SIZE         65536
#define RTE_PATTERN_TEMPLATE_SIZE        4

#define RTE_QUEUE_OFFSET_MULT                   4
#define RTE_SRC_CREATE_RULE_QUEUE_OFFSET        0
#define RTE_DST_CREATE_RULE_QUEUE_OFFSET        1
#define RTE_SRC_FLOW_MANAGER_QUEUE_OFFSET       2
#define RTE_DST_FLOW_MANAGER_QUEUE_OFFSET       3

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

typedef struct RteFlowHandlerToFlow_ {
    Flow *flow;
    struct rte_flow *src_handle;
    struct rte_flow *dst_handle;
    struct rte_flow_action_handle *src_action_handle;
    struct rte_flow_action_handle *dst_action_handle;
    RteFlowBypassData *rte_flow_bypass_data;
    uint16_t livedev_id;
    uint16_t in_queue_id;
} RteFlowHandlerToFlow;

static uint32_t RteFlowBypassGetBypassInfoMPSize(const char *, uint32_t *);
static void RteFlowRuleDestroy(uint16_t, uint16_t, struct rte_flow *, struct rte_flow_action_handle *, void *);
static void RteFlowHandleEmergency(ThreadVars *, Flow *, void *);
static int RteFlowUpdateStats(FlowBypassInfo *,  LiveDevice *, RteFlowHandlerToFlow *);
int RteFlowCheckRules(ThreadVars *, struct flows_stats *, struct timespec *, void *);
static void RteFlowSetFlowBypassInfo(FlowBypassInfo *,
        Flow *, struct rte_flow *, struct rte_flow *, struct rte_flow_action_handle *, struct rte_flow_action_handle *, int);
static uint32_t DeviceDecideRteFlowRulesCapacity(const char *);
static int RteFlowBypassAsyncInit(uint16_t, const char *, RteFlowBypassData *);
static int RteFlowJumpRuleTemplateInit(uint16_t, RteFlowBypassData *);
static struct rte_flow_action_handle *
RteFlowCreateIndirectAction(int, uint32_t, struct rte_flow_action *);

static uint16_t rte_bypass_manager_queue_id;
static uint16_t rte_flow_manager_queue_id;

/**
 * \brief Retrieve dpdk.capture-bypass and set it to all interfaces.
 *
 * Get dpdk.capture-bypass flag for enabling rte_flow bypass.
 * Set this global flag to each interface.
 * Default setting is disabled.
 *
 * \param capture_bypass_str value to look for in suricata.yaml
 * \param capture_bypass_enabled pointer to save gathered value
 * \return 1 if bypass enabled, 0 if disabled
 */
int ConfigSetCaptureBypass(DPDKIfaceConfig *iconf)
{
    SCEnter();
    int entry_bool = 0;
    int retval = SCConfGetBool("dpdk.capture-bypass", &entry_bool);
    if (retval != 1) {
        iconf->capture_bypass_enabled = false;
    } else {
        iconf->capture_bypass_enabled = entry_bool;
        retval = entry_bool;
    }
    SCReturnInt(retval);
}

/**
 * \brief Get bypass-info mempool size from config.
 *
 * \param driver_name name of the driver
 * \param[out] bypass_info_mp_size size of the mempool
 * \return 0 on success, negative value on error
 */
static uint32_t RteFlowBypassGetBypassInfoMPSize(
        const char *driver_name, uint32_t *bypass_info_mp_size)
{
    SCEnter();
    SCConfNode *dpdk_root = SCConfGetNode("dpdk");

    /* We are not taking into consideration the number of drop-filter rules here,
       because we want to have a mempool of size (2^n)-1 */
    uint32_t max_sz = DeviceDecideRteFlowRulesCapacity(driver_name) - 1;
    uint32_t sz = 0;

    const char *entry_str = NULL;
    int ret = SCConfGetChildValue(dpdk_root, "bypass-info-mp-size", &entry_str);
    /* Set to maximum if value is "auto" or missing */
    if (ret != 1 || strcmp(entry_str, "auto") == 0) {
        sz = max_sz;
    } else {
        if (StringParseUint32(&sz, 10, 0, entry_str) < 0) {
            SCLogError("bypass-info-mp-size contains non-numerical characters - \"%s\"", entry_str);
            SCReturnInt(-EINVAL);
        }
    }

    if (sz > max_sz) {
        SCLogConfig("bypass-info-mp-size too big (%d), setting it to driver (%s) maximum: %d", sz,
                driver_name, max_sz);
        sz = max_sz;
    } else {
        SCLogConfig("bypass-info-mp-size set to %d", sz);
    }
    *bypass_info_mp_size = sz;
    SCReturnInt(0);
}

/**
 * \brief Decide what is the maximal capacity of dynamic bypass rte_flow rules the device can
 * handle.
 *
 * \param driver_name name of the driver
 * \return uint32_t count of rte_flow bypass rules the device can utilize
 */
static uint32_t DeviceDecideRteFlowRulesCapacity(const char *driver_name)
{
    uint32_t retval = 0;
    if (strcmp(driver_name, "mlx5_pci") == 0)
        retval = MLX5_RTE_FLOW_RULES_CAPACITY;
    return retval;
}

/**
 * \brief Initialize Template API resources for dynamic bypass rules.
 *
 * Creates a single template table with relaxed matching that supports
 * IPv4/IPv6 + TCP/UDP combinations. The pattern template, actions template,
 * and template table are stored in RteFlowBypassData for later use.
 *
 * \param port_id  DPDK port identifier
 * \param data bypass data structure to populate
 * \return 0 on success, -1 on error
 */
int RteFlowTemplateResourcesInit(uint16_t port_id, RteFlowBypassData *data)
{
    SCEnter();
    /* Memory alloc */
    RteFlowTemplateResources *bypass_resources_ipv4 = SCCalloc(1, sizeof(RteFlowTemplateResources));
    if (bypass_resources_ipv4 == NULL) {
        SCLogError("rte_flow dynamic bypass: Failed to allocate memory for Template API resources");
        SCReturnInt(-ENOMEM);
    }
    RteFlowTemplateResources *bypass_resources_ipv6 = SCCalloc(1, sizeof(RteFlowTemplateResources));
    if (bypass_resources_ipv6 == NULL) {
        SCLogError("rte_flow dynamic bypass: Failed to allocate memory for Template API resources");
        SCReturnInt(-ENOMEM);
    }
    /* Bypass rules pattern template setup */
    struct rte_flow_item pattern_template[] = { { 0 }, { 0 }, { 0 }, { 0 } };
    uint16_t L2_INDEX = 0, L3_INDEX = 1, L4_INDEX = 2, END_INDEX = 3;
    pattern_template[L2_INDEX].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern_template[END_INDEX].type = RTE_FLOW_ITEM_TYPE_END;

    struct rte_flow_item_ipv4 ipv4_spec = { 0 };
	struct rte_flow_item_ipv4 ipv4_mask = {
		.hdr = {
			.src_addr = 0xFFFFFFFF,
			.dst_addr = 0xFFFFFFFF,
		}
	};

    struct rte_flow_item_ipv6 ipv6_spec = {0};
    struct rte_flow_item_ipv6 ipv6_mask = {0};
    memset(ipv6_mask.hdr.src_addr, 0xFF, 16);
    memset(ipv6_mask.hdr.dst_addr, 0xFF, 16);

	struct rte_flow_item_tcp tcp_spec = {0};
	struct rte_flow_item_tcp tcp_mask = {
		.hdr = {
			.src_port = 0xFFFF,
			.dst_port = 0xFFFF,
		}
	};
	struct rte_flow_item_tcp udp_spec = {0};
	struct rte_flow_item_tcp udp_mask = {
		.hdr = {
			.src_port = 0xFFFF,
			.dst_port = 0xFFFF,
		}
	};

    pattern_template[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern_template[L3_INDEX].spec = &ipv4_spec;
    pattern_template[L3_INDEX].mask = &ipv4_mask;
    pattern_template[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern_template[L4_INDEX].spec = &tcp_spec;
    pattern_template[L4_INDEX].mask = &tcp_mask;
    bypass_resources_ipv4->pt[RTE_PATTERN_TEMPLATE_TCP] = RteFlowCreatePatternTemplate(
            port_id, pattern_template);
    
    pattern_template[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern_template[L4_INDEX].spec = &udp_spec;
    pattern_template[L4_INDEX].mask = &udp_mask;
    bypass_resources_ipv4->pt[RTE_PATTERN_TEMPLATE_UDP] = RteFlowCreatePatternTemplate(
            port_id, pattern_template);

    pattern_template[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern_template[L3_INDEX].spec = &ipv6_spec;
    pattern_template[L3_INDEX].mask = &ipv6_mask;
    pattern_template[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern_template[L4_INDEX].spec = &tcp_spec;
    pattern_template[L4_INDEX].mask = &tcp_mask;
    bypass_resources_ipv6->pt[RTE_PATTERN_TEMPLATE_TCP] = RteFlowCreatePatternTemplate(
            port_id, pattern_template);

    pattern_template[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern_template[L4_INDEX].spec = &udp_spec;
    pattern_template[L4_INDEX].mask = &udp_mask;
    bypass_resources_ipv6->pt[RTE_PATTERN_TEMPLATE_UDP] = RteFlowCreatePatternTemplate(
            port_id, pattern_template);
    
    bypass_resources_ipv4->pt_cnt = 2;
    bypass_resources_ipv6->pt_cnt = 2;
    for (int i = 0; i < bypass_resources_ipv4->pt_cnt; i++) {
        if (bypass_resources_ipv4->pt[i] == NULL || bypass_resources_ipv6->pt[i] == NULL) {
            goto cleanup;
        }
    }

    /* Bypass rules actions template setup */
    struct rte_flow_action actions_template[] = {
        [0] = { .type = RTE_FLOW_ACTION_TYPE_INDIRECT },
        [1] = { .type = RTE_FLOW_ACTION_TYPE_DROP },
        [2] = { .type = RTE_FLOW_ACTION_TYPE_END },
    };
    struct rte_flow_action actions_masks_template[] = {
        [0] = { .type = RTE_FLOW_ACTION_TYPE_COUNT },
        [1] = { .type = RTE_FLOW_ACTION_TYPE_DROP },
        [2] = { .type = RTE_FLOW_ACTION_TYPE_END },
    };
    bypass_resources_ipv4->at = RteFlowCreateActionTemplate(
            port_id, actions_template, actions_masks_template);
    if (bypass_resources_ipv4->at == NULL) {
       goto cleanup;
    }
    bypass_resources_ipv6->at = RteFlowCreateActionTemplate(
            port_id, actions_template, actions_masks_template);
    if (bypass_resources_ipv6->at == NULL) {
       goto cleanup;
    }

    /* Bypass rules template table setup */
    bypass_resources_ipv4->tbl = RteFlowCreateTemplateTable(
            port_id, RTE_JUMP_GROUP, RTE_RULE_PRIORITY_0, data->bypass_info_mp->size, bypass_resources_ipv4->pt, bypass_resources_ipv4->pt_cnt, &bypass_resources_ipv4->at, 1);
    if (bypass_resources_ipv4->tbl == NULL) {
        goto cleanup;
    }
//    bypass_resources_ipv6->tbl = RteFlowCreateTemplateTable(
//             port_id, RTE_JUMP_GROUP, RTE_RULE_PRIORITY_1, data->bypass_info_mp->size, bypass_resources_ipv6->pt, bypass_resources_ipv6->pt_cnt, &bypass_resources_ipv6->at, 1);
//     if (bypass_resources_ipv6->tbl == NULL) {
//         goto cleanup;
//     }

    data->bypass_resources_ipv4 = bypass_resources_ipv4;
    // data->bypass_resources_ipv6 = bypass_resources_ipv6;
    SCReturnInt(0);

cleanup:
    SCLogError("rte_flow_bypass: bypass template failed");
    RteFlowTemplateResourcesFree(port_id, bypass_resources_ipv4);
    RteFlowTemplateResourcesFree(port_id, bypass_resources_ipv6);
    data->bypass_resources_ipv4 = NULL;
    data->bypass_resources_ipv6 = NULL;
    SCReturn(-1);
}

/**
 * \brief Free Template API resources.
 *
 * \param port_id DPDK port identifier
 * \param template_resources resources to free
 */
void RteFlowTemplateResourcesFree(uint16_t port_id, RteFlowTemplateResources *template_resources)
{
    struct rte_flow_error flow_error = { 0 };
    if (template_resources == NULL) {
        SCReturn;
    }
    if (template_resources->tbl != NULL) {
        rte_flow_template_table_destroy(port_id, template_resources->tbl, &flow_error);
        template_resources->tbl = NULL;
    }
    if (template_resources->at != NULL) {
        rte_flow_actions_template_destroy(port_id, template_resources->at, &flow_error);
        template_resources->at = NULL;
    }
    for (int i = 0; i < template_resources->pt_cnt; i++) {
        if (template_resources->pt[i] != NULL) {
            rte_flow_pattern_template_destroy(port_id, template_resources->pt[i], &flow_error);
            template_resources->pt[i] = NULL;
        }
    }
    SCFree(template_resources);
}

/** 
 * \brief Create a pattern template for dynamic bypass rules.
 * 
 * \param port_id DPDK port identifier
 * \param pattern array of flow items for the template
 * \return pointer to the created pattern template, or NULL on error
 */
struct rte_flow_pattern_template *
RteFlowCreatePatternTemplate(int port_id, struct rte_flow_item *pattern)
{
    struct rte_flow_error error = { 0 };
	struct rte_flow_pattern_template_attr attr = { .ingress = 1, };

	struct rte_flow_pattern_template *templ =
		rte_flow_pattern_template_create(port_id, &attr, pattern, &error);

	if (!templ)
		SCLogError("rte_flow_pattern_template_create() failed: %s\n", error.message);

	return templ;
}

/** 
 * \brief Create an actions template for dynamic bypass rules.
 * 
 * \param port_id DPDK port identifier
 * \param actions array of actions for the template
 * \param masks array of masks for the actions
 * \return pointer to the created actions template, or NULL on error
 */
struct rte_flow_actions_template *
RteFlowCreateActionTemplate(int port_id, struct rte_flow_action *actions, struct rte_flow_action *masks)
{
    struct rte_flow_error error = { 0 };
	struct rte_flow_actions_template_attr attr = { .ingress = 1, };

	struct rte_flow_actions_template *templ =
		rte_flow_actions_template_create(port_id, &attr, actions, masks, &error);

	if (!templ)
		SCLogError("rte_flow_actions_template_create() failed: %s\n", error.message);

	return templ;
}

/**
 * \brief Create a template table for dynamic bypass rules.
 *
 * \param port_id DPDK port identifier
 * \param group group number for the template table
 * \param priority priority for the flow rules in this template table
 * \param nb_flows number of flows the table can hold
 * \param ptempls array of pattern templates
 * \param nb_ptempls number of pattern templates
 * \param atempls array of actions templates
 * \param nb_atempls number of actions templates
 * \return pointer to the created template table, or NULL on error
 */
struct rte_flow_template_table *
RteFlowCreateTemplateTable(int port_id, uint32_t group, uint32_t priority, uint32_t nb_flows,
					  struct rte_flow_pattern_template **ptempls, uint32_t nb_ptempls,
					  struct rte_flow_actions_template **atempls, uint32_t nb_atempls)
{
    struct rte_flow_error error = { 0 };
	struct rte_flow_template_table_attr attr = {
		.flow_attr = {
			.group = group,
			.priority = priority,
			.ingress = 1,
		},
		.nb_flows = nb_flows,
	};

	struct rte_flow_template_table *table = rte_flow_template_table_create(
		port_id, &attr, ptempls, nb_ptempls, atempls, nb_atempls, &error);

	if (!table)
		SCLogError("rte_flow_template_table_create() failed: %s\n", error.message);

	return table;
}

/**
 * \brief Create an indirect action for dynamic bypass rules.
 * 
 * \param port_id DPDK port identifier
 * \param queue_id DPDK queue identifier
 * \param action pointer to the action to create an indirect handle for
 * \return pointer to the created indirect action handle, or NULL on error
 */
static struct rte_flow_action_handle *
RteFlowCreateIndirectAction(int port_id, uint32_t queue_id, struct rte_flow_action *action)
{
    struct rte_flow_error error = { 0 };
	struct rte_flow_op_attr op_attr = { .postpone = 0 };
	struct rte_flow_indir_action_conf indir_conf = { .ingress = 1 };

	struct rte_flow_action_handle *handle = rte_flow_async_action_handle_create(
		port_id, queue_id, &op_attr, &indir_conf, action, NULL, &error);

	if (!handle)
		SCLogError("rte_flow_async_action_handle_create() failed: %s\n", error.message);

	return handle;
}

/** \brief
 * 
 * \param port_id
 * \param queue_id
 * \param table
 * \param pattern
 * \param pt_index
 * \param actions
 * \param at_index
 * \param user_data
 */
struct rte_flow *
RteFlowCreateRuleAsync(int port_id, uint32_t queue_id, struct rte_flow_template_table *table,
				  struct rte_flow_item *pattern, uint8_t pt_index, struct rte_flow_action *actions, uint8_t at_index, void *user_data)
{
    struct rte_flow_error error = { 0 };
	struct rte_flow_op_attr op_attr = { .postpone = 0 };

	struct rte_flow *flow = rte_flow_async_create(
		port_id, queue_id, &op_attr, table,
		pattern, pt_index, actions, at_index, user_data, &error);

	if (!flow)
		SCLogError("rte_flow_async_create() failed: %s\n", error.message);

	return flow;
}

/**
 * \brief Drain the completions of this worker's own rte_flow queues.
 *
 * The mlx5 HWS PMD requires each flow queue to be owned by a single thread
 * for all operations (create / destroy / query / push / pull). Its per-queue
 * job LIFO (hw_q[].job_idx) is not protected by locks or atomics, so having
 * another thread (e.g. the bypass manager) pull a queue that a worker posts
 * to is a data race that corrupts the completions and crashes the PMD at
 * mlx5_flow_hw.c:3941 (job->flow->res_idx).
 *
 * This function is meant to be called from the worker thread's receive loop.
 * It pushes and drains the two queues owned by this worker (2*queue_id and
 * 2*queue_id+1), and reports rule-load failures so they can be counted.
 *
 * \param port_id DPDK port identifier
 * \param queue_id RX queue id of this worker (maps to rte_flow queues 2*q and 2*q+1)
 * \param bypass_data bypass data structure for stats counters
 */
void RteFlowWorkerDrain(uint16_t port_id, uint16_t queue_id, RteFlowBypassData *bypass_data)
{
    if (bypass_data == NULL) {
        return;
    }
    const int max_res_size = 1024;
    struct rte_flow_op_result res[max_res_size];
    struct rte_flow_error error = { 0 };
    /* This worker is the sole producer/consumer of these two queues. */
    uint16_t queues[2] = { (uint16_t)(2 * queue_id), (uint16_t)(2 * queue_id + 1) };

    for (int q = 0; q < 2; q++) {
        int retval = rte_flow_push(port_id, queues[q], &error);
        if (retval != 0) {
            SCLogWarning("rte_flow bypass: worker push failed on queue %u: %s",
                    queues[q], error.message);
            continue;
        }
        int pull_cnt;
        do {
            pull_cnt = rte_flow_pull(port_id, queues[q], res, max_res_size, &error);
            if (pull_cnt < 0) {
                SCLogWarning("rte_flow bypass: worker pull failed on queue %u: %s",
                        queues[q], error.message);
                break;
            }
            for (int i = 0; i < pull_cnt; i++) {
                if (res[i].status != 0 && res[i].user_data != NULL) {
                    RteFlowHandlerToFlow *flow_handler_info =
                            (RteFlowHandlerToFlow *)res[i].user_data;
                    FLOWLOCK_WRLOCK(flow_handler_info->flow);
                    FlowUpdateState(flow_handler_info->flow, FLOW_STATE_LOCAL_BYPASSED);
                    FLOWLOCK_UNLOCK(flow_handler_info->flow);
                    SC_ATOMIC_ADD(bypass_data->rte_bypass_flows_bypass_error, 1);
                }
            }
        } while (pull_cnt == max_res_size);
    }
}

/**
 * \brief Initialize the async jump rule (group 0 -> group 1).
 * \param data bypass data structure to populate with jump rule handles
 * \param port_id DPDK port identifier
 * \return 0 on success, -1 on error
 */
static int RteFlowJumpRuleTemplateInit(uint16_t port_id, RteFlowBypassData *data)
{
    SCEnter();
    RteFlowTemplateResources *jump_resources = SCCalloc(1, sizeof(RteFlowTemplateResources));
    if (jump_resources == NULL) {
        SCLogError("rte_flow dynamic bypass: Failed to allocate memory for jump rule Template API resources");
        SCReturnInt(-ENOMEM);
    }

	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_END }
	};
    jump_resources->pt_cnt = 1;
	struct rte_flow_action actions[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_JUMP },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};
	struct rte_flow_action actions_mask[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_JUMP },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

	jump_resources->pt[RTE_PATTERN_TEMPLATE_DEFAULT] = RteFlowCreatePatternTemplate(port_id, pattern);
	jump_resources->at = RteFlowCreateActionTemplate(port_id, actions, actions_mask);
    if (jump_resources->pt[RTE_PATTERN_TEMPLATE_DEFAULT] == NULL || jump_resources->at == NULL) {
        goto cleanup;
    }
	jump_resources->tbl = RteFlowCreateTemplateTable(port_id, RTE_DEFAULT_GROUP, RTE_RULE_PRIORITY_0, 1, &jump_resources->pt[RTE_PATTERN_TEMPLATE_DEFAULT], 1, &jump_resources->at, 1);
    if (jump_resources->tbl == NULL) {
        goto cleanup;
    }
    data->jump_resources = jump_resources;
    SCReturn(0);

cleanup:
    SCLogError("rte_flow_bypass: jump rule template failed");
    RteFlowTemplateResourcesFree(port_id, data->jump_resources);
    data->jump_resources = NULL;
    SCReturnInt(-1);
}

/** 
 * \brief Create a rule that redirects all traffic from the default rte_flow group to the group where the bypass rte_flow rules reside.
 * 
 * \param data bypass data structure
 * \param port_id DPDK port identifier
 * \return 0 on success, -1 on error
 */
int RteFlowCreateJumpRule(uint16_t port_id, const char *port_name, RteFlowBypassData *data)
{
    SCEnter();
	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_END }
	};

	struct rte_flow_action_jump jump_conf = { .group = RTE_JUMP_GROUP };
	struct rte_flow_action actions[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_JUMP, .conf = &jump_conf },
		{ .type = RTE_FLOW_ACTION_TYPE_END }
	};

	struct rte_flow *rule_handle = RteFlowCreateRuleAsync(port_id, RTE_FLOW_QUEUE_ID, data->jump_resources->tbl,
								   pattern, RTE_PATTERN_TEMPLATE_DEFAULT, actions, RTE_ACTIONS_TEMPLATE_DEFAULT, NULL);
    if (rule_handle == NULL) {
        SCReturnInt(-1);
    }

    struct rte_flow_error flow_error = { 0 };
    struct rte_flow_op_result res = {0};
    rte_delay_ms(500);
    int retval = rte_flow_pull(port_id, RTE_FLOW_QUEUE_ID, &res, 1, &flow_error);
    if (retval < 0) {
        SCLogError("%s: rte_flow_pull jump error: %s", port_name, rte_strerror(-retval));
        SCReturnInt(retval);
    } else if (retval > 0) {
        SCLogInfo("%s: result for jump rule: %d", port_name, res.status);
    } else {
        SCLogInfo("%s: No result for jump rule yet", port_name);
    }
    SCReturnInt(0);
}

static int RteFlowBypassAsyncInit(uint16_t port_id, const char *port_name, RteFlowBypassData *rte_flow_bypass_data)
{

    struct rte_flow_port_attr port_attr = {
        .host_port_id = port_id,
        .nb_counters = rte_flow_bypass_data->rte_bypass_rule_capacity,
    };
    struct rte_flow_queue_attr queue_attr = {
        .size = 1024,
    };

    uint16_t nb_rx_queues = rte_flow_bypass_data->nb_rx_queues;
    /* Create as many queues as there are workers and additional 1 for flow manager and 1 for bypass manager */
    uint16_t rte_flow_async_queues  = (RTE_QUEUE_OFFSET_MULT * nb_rx_queues) + 2;
    rte_bypass_manager_queue_id = rte_flow_async_queues - 1;
    rte_flow_manager_queue_id = rte_flow_async_queues  - 2;
    const struct rte_flow_queue_attr *queue_attrs[rte_flow_async_queues];
    for (uint16_t i = 0; i < rte_flow_async_queues; i++) {
        queue_attrs[i] = &queue_attr;
    }

    struct rte_flow_error flow_error = { 0 };
    int retval = rte_flow_configure(
        port_id, &port_attr, rte_flow_async_queues, queue_attrs, &flow_error);
    if (retval < 0) { 
        SCLogError("%s: rte_flow_configure failed: %s", port_name, flow_error.message);
        SCReturnInt(retval);
    }

    /* Prepare template resources */
    retval = RteFlowTemplateResourcesInit(port_id, rte_flow_bypass_data);
    if (retval != 0)
        SCReturnInt(retval);

    /* Prepare the jump rule */
    retval = RteFlowJumpRuleTemplateInit(port_id, rte_flow_bypass_data);
    if (retval != 0) {
        RteFlowTemplateResourcesFree(port_id, rte_flow_bypass_data->bypass_resources_ipv4);
        RteFlowTemplateResourcesFree(port_id, rte_flow_bypass_data->bypass_resources_ipv6);
        SCReturnInt(retval);
    }
    SCReturnInt(0);
}

/**
 * \brief Enable and register functions for BypassManager,
 *        initialize rte_ring data structure and store in global
 *        variable
 *
 * \param iconf configuration of the interface
 * \return int 0 on success, negative value on error
 */
int RteBypassInit(DPDKIfaceConfig *iconf, const char *driver_name)
{
    SCEnter();
    static RteFlowBypassData *rte_flow_bypass_data = NULL;
    char *port_name = iconf->iface;
    LiveDevice *livedev = LiveGetDevice(port_name);
    LiveDevUseBypass(livedev);
    int retval = 0;

    /* If the bypass data is already allocated,
       the bypass is ready and we need only to decrease the rte_flow rules capacity
       by number of drop-filter rules present on this interface */
    if (rte_flow_bypass_data != NULL) {
        iconf->dpdk_dev_resources->rte_flow_bypass_data = rte_flow_bypass_data;
        SCReturnInt(retval);
    }

    RunModeEnablesBypassManager();
    rte_flow_bypass_data = SCCalloc(1, sizeof(RteFlowBypassData));
    if (rte_flow_bypass_data == NULL) {
        SCLogError("%s: Memory allocation for RteFlowBypassData failed", port_name);
        SCReturnInt(-ENOMEM);
    }

    /* We set the bypass_info_mp size to the capacity of the underlying hardware */
    uint32_t bypass_info_mempool_size;
    retval = RteFlowBypassGetBypassInfoMPSize(driver_name, &bypass_info_mempool_size);
    if (retval < 0) {
        goto cleanup;
    }
    struct rte_mempool *bypass_info_mp = rte_mempool_create(RTE_BYPASS_INFO_MEMPOOL_NAME,
            bypass_info_mempool_size, sizeof(RteFlowHandlerToFlow),
            MempoolCacheSizeCalculate(bypass_info_mempool_size), 0, NULL, NULL, NULL, NULL,
            rte_socket_id(), 0);
    if (bypass_info_mp == NULL) {
        SCLogError("%s: rte_mempool_create failed (mempool: %s): %s", port_name,
                RTE_BYPASS_INFO_MEMPOOL_NAME, rte_strerror(rte_errno));
        retval = -1;
        goto cleanup;
    }
    rte_flow_bypass_data->bypass_info_mp = bypass_info_mp;
    
    rte_flow_bypass_data->nb_rx_queues = iconf->nb_rx_queues;

    BypassedFlowManagerRegisterCheckFunc(RteFlowCheckRules, NULL, (void *)rte_flow_bypass_data);

    rte_flow_bypass_data->rte_bypass_rule_capacity =
            DeviceDecideRteFlowRulesCapacity(driver_name);

    /* Destroys rte_flow rules of bypassed flows evicted during emergency mode */
    // SCFlowRegisterFinishCallback(RteFlowHandleEmergency, NULL);

    retval = RteFlowBypassAsyncInit(iconf->port_id, port_name, rte_flow_bypass_data);
    if (retval < 0) {
        goto cleanup;
    }
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_rules_active);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_rules_created);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_rules_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_flows_bypass_success);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_flows_bypass_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_flow_lookup_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_mempool_key_get_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_mempool_info_get_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_query_error);

    iconf->dpdk_dev_resources->rte_flow_bypass_data = rte_flow_bypass_data;

    SCReturnInt(retval);

cleanup:
    RteFlowTemplateResourcesFree(iconf->port_id, rte_flow_bypass_data->bypass_resources_ipv4);
    RteFlowTemplateResourcesFree(iconf->port_id, rte_flow_bypass_data->bypass_resources_ipv6);
    SCFree(rte_flow_bypass_data);
    SCReturnInt(retval);
}

int RteFlowCheckRules(ThreadVars *th_v, struct flows_stats *bypassstats, struct timespec *curtime, void *data)
{
    RteFlowBypassData *bypass_data = (RteFlowBypassData *)data;

    /* Worker threads own and drain their own per-queue completions to avoid
     * racing on the PMD's per-queue job LIFO (data race on hw_q[].job_idx).
     * The bypass manager only needs to handle operation failures discovered
     * by the workers; they are counted via rte_bypass_flows_bypass_error.
     * Nothing to do here - rule status handling happens per-worker.
     */
    SCReturnInt(0);
}

/**
 * \brief Decides whether the rte_flow rule should be removed from the table
 *
 * \param port_id identificator of a port
 * \param src_rule_handler rte_flow rule handler for specific flow in one direction
 * \param dst_rule_handler rte_flow rule handler for specific flow in other direction
 * \param flow flow to be possibly removed from the table
 * \return int 1 if the rte_flow rule is active, 0 if it should be removed
 */
static int RteFlowUpdateStats(FlowBypassInfo *fc, LiveDevice *livedev, RteFlowHandlerToFlow *flow_handler_info)
{
    struct rte_flow_op_attr op_attr = { .postpone = 1 };
    struct rte_flow_query_count query_count = {0};
    struct rte_flow_error error;
    uint64_t src_packets = 0, src_bytes = 0, dst_packets = 0, dst_bytes = 0;
    uint16_t port_id = livedev->dpdk_vars->port_id;

    query_count.reset = 1;
	int retval = rte_flow_async_action_handle_query(port_id, rte_flow_manager_queue_id, &op_attr,
										 flow_handler_info->src_action_handle, &query_count, flow_handler_info, &error);
	if (retval != 0) {
		SCLogWarning("rte_flow_async_action_handle_query() failed: %d with: %s\n", retval, error.message);
        SC_ATOMIC_ADD(livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_query_error, 1);
    } else {
        src_packets += query_count.hits;
        src_bytes += query_count.bytes;
    }

    memset(&query_count, 0, sizeof(struct rte_flow_query_count));
    query_count.reset = 1;

    retval = rte_flow_async_action_handle_query(port_id, rte_flow_manager_queue_id, &op_attr,
										 flow_handler_info->dst_action_handle, &query_count, flow_handler_info, &error);
    if (retval != 0)  {
        SCLogWarning("rte_flow_async_action_handle_query() failed: %d with: %s\n", retval, error.message);
        SC_ATOMIC_ADD(livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_query_error, 1);
    } else {
        dst_packets += query_count.hits;
        dst_bytes += query_count.bytes;
    }
    
    /* The flow manager thread is the sole producer/consumer of the manager
     * queue, so pushing a batch and pulling its completions here is safe.
     */
    retval = rte_flow_push(port_id, rte_flow_manager_queue_id, &error);
    if (retval != 0) {
        SCLogWarning("UpdateStats rte_flow_push() failed: %s", error.message);
    }

    int max_res_size = 1024;
    struct rte_flow_op_result res[max_res_size];
    retval = rte_flow_pull(port_id, rte_flow_manager_queue_id, res, max_res_size, &error);
    if (retval < 0) {
        SCLogWarning("UpdateStats rte_flow_pull() failed: %s", error.message);
    } else {
        for (int i = 0; i < retval; i++) {
            if (res[i].status != 0 && res[i].user_data != NULL) {
                SCLogWarning("UpdateStats rte_flow_pull Not OK: status=%d user_data=%p", res[i].status, res[i].user_data);
            }
        }
    }
    /* Proceed only if there are new filtered packets in the flow */
    if (src_packets || dst_packets) {
        fc->tosrcpktcnt += src_packets;
        fc->tosrcbytecnt += src_bytes;
        fc->todstpktcnt += dst_packets;
        fc->todstbytecnt += dst_bytes;
        SCReturnInt(1);
    }
    SCReturnInt(0);
}

// static void RteFlowHandleEmergency(ThreadVars *tv, Flow *f, void *data)
// {
//     if (f->flow_state != FLOW_STATE_CAPTURE_BYPASSED &&
//             (f->flow_end_flags & FLOW_END_FLAG_EMERGENCY) == 0) {
//         return;
//     }
//     FlowBypassInfo *fc = SCFlowGetStorageById(f, GetFlowBypassInfoID());
//     if (fc == NULL)
//         return;
//     RteFlowHandlerToFlow *flow_handler_info = (RteFlowHandlerToFlow *)fc->bypass_data;
//     if (flow_handler_info == NULL)
//         return;
//     if (flow_handler_info->src_handler != NULL && flow_handler_info->dst_handler != NULL) {
//         RteFlowRuleDestroy(flow_handler_info->rte_flow_bypass_data, flow_handler_info->livedev->dpdk_vars->port_id,
//                 flow_handler_info->src_handler, flow_handler_info->dst_handler);
//         flow_handler_info->src_handler = NULL;
//         flow_handler_info->dst_handler = NULL;
//         SC_ATOMIC_SUB(flow_handler_info->rte_flow_bypass_data->rte_bypass_rules_active, 2);
//     }
// }

/**
 * \brief Destroy rte_flow rules for both directions of a flow
 *
 * \param port_id identifier of a port
 * \param src_handler handler of rte_flow rule
 * \param dst_handler handler of rte_flow rule
 */
static void RteFlowRuleDestroy(
        uint16_t port_id, uint16_t queue_id, struct rte_flow *rule_handle, struct rte_flow_action_handle *action_handle, void *user_data)
{
    const struct rte_flow_op_attr op_attr = { .postpone = 0 };
    int retval = 0;
    struct rte_flow_error flow_error = { 0 };
    if (action_handle != NULL) {
        retval = rte_flow_async_action_handle_destroy(port_id, queue_id, &op_attr, action_handle, user_data, &flow_error);
        if (retval != 0) {
            SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                    rte_strerror(-retval), flow_error.message);
            }
    }
    if (rule_handle != NULL) {
        retval = rte_flow_async_destroy(port_id, queue_id, &op_attr, rule_handle, user_data, &flow_error);
        if (retval != 0) {
            SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                    rte_strerror(-retval), flow_error.message);
        }
    }

    const int max_res_size = 1024;
    struct rte_flow_op_result res[max_res_size];
    int pull_cnt;
    do {
        pull_cnt = rte_flow_pull(port_id, queue_id, res, max_res_size, &flow_error);
        if (pull_cnt < 0) {
            SCLogWarning("rte_flow bypass: worker pull failed on queue %u: %s",
                    queue_id, flow_error.message);
            break;
        }
        for (int i = 0; i < pull_cnt; i++) {
            if (res[i].status != 0 && res[i].user_data != NULL) {
                RteFlowHandlerToFlow *flow_handler_info =
                        (RteFlowHandlerToFlow *)res[i].user_data;
                FLOWLOCK_WRLOCK(flow_handler_info->flow);
                FlowUpdateState(flow_handler_info->flow, FLOW_STATE_LOCAL_BYPASSED);
                FLOWLOCK_UNLOCK(flow_handler_info->flow);
            }
        }
    } while (pull_cnt == max_res_size);

}

void RteBypassFree(void *data)
{
    RteFlowHandlerToFlow *flow_handler_info = (RteFlowHandlerToFlow *)data;
    if (flow_handler_info == NULL) {
        return;
    }
    LiveDevice *livedev = LiveDeviceGetById(flow_handler_info->livedev_id);
    if (livedev && livedev->dpdk_vars && livedev->dpdk_vars->rte_flow_bypass_data) {
        rte_mempool_put(
                livedev->dpdk_vars->rte_flow_bypass_data->bypass_info_mp, flow_handler_info);
    }
}

bool RteBypassUpdate(Flow *flow, void *data, time_t tsec)
{
    RteFlowHandlerToFlow *flow_handler_info = (RteFlowHandlerToFlow *)data;
    if (flow_handler_info == NULL) {
        /* Data already freed */
        return false;
    }
    FlowBypassInfo *fc = SCFlowGetStorageById(flow, GetFlowBypassInfoID());
    if (fc == NULL) {
        /* Data already freed */
        return false;
    }
    if (flow_handler_info->src_handle == NULL || flow_handler_info->dst_handle == NULL) {
        /* Rules already deleted */
        return false;
    }
    LiveDevice *livedev = LiveDeviceGetById(flow->livedev_id);
    bool activity = RteFlowUpdateStats(
            fc, livedev, flow_handler_info);

    if (activity)
        flow->lastts = SCTIME_FROM_SECS(tsec);

    /* At shutdown, we only get the counters. We delete the rules with rte_flow_flush later */
    if (unlikely(suricata_ctl_flags != 0)) {
        flow_handler_info->src_handle = NULL;
        flow_handler_info->dst_handle = NULL;
        SC_ATOMIC_SUB(livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_rules_active, 2);
        return activity;
    }

    if (!activity) {
        if (flow_handler_info->src_handle != NULL && flow_handler_info->dst_handle != NULL) {
            uint16_t base_queue_id = flow_handler_info->in_queue_id * RTE_QUEUE_OFFSET_MULT;
            RteFlowRuleDestroy(livedev->dpdk_vars->port_id, base_queue_id + RTE_SRC_FLOW_MANAGER_QUEUE_OFFSET, flow_handler_info->src_handle, flow_handler_info->src_action_handle, flow_handler_info);
            RteFlowRuleDestroy(livedev->dpdk_vars->port_id, base_queue_id + RTE_DST_FLOW_MANAGER_QUEUE_OFFSET, flow_handler_info->dst_handle, flow_handler_info->dst_action_handle, flow_handler_info);
            flow_handler_info->src_handle = NULL;
            flow_handler_info->dst_handle = NULL;
            SC_ATOMIC_SUB(livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_rules_active, 2);
        }
    }
    SCReturnBool(activity);
}

static void RteFlowSetFlowBypassInfo(FlowBypassInfo *fc,
        Flow *flow, struct rte_flow *src_handler, struct rte_flow *dst_handler, struct rte_flow_action_handle *src_action_handle, struct rte_flow_action_handle *dst_action_handle, int family)
{
    LiveDevice *livedev = LiveDeviceGetById(flow->livedev_id);
    RteFlowHandlerToFlow *flow_handler_info = (RteFlowHandlerToFlow *)fc->bypass_data;
    flow_handler_info->flow = flow;
    flow_handler_info->src_handle = src_handler;
    flow_handler_info->src_action_handle = src_action_handle;
    flow_handler_info->dst_handle = dst_handler;
    flow_handler_info->dst_action_handle = dst_action_handle;
    flow_handler_info->livedev_id = livedev->id;
    fc->bypass_data = flow_handler_info;
    fc->BypassUpdate = RteBypassUpdate;
    fc->BypassFree = RteBypassFree;
}

/** \brief Create hardware (rte_flow) rule for the incomign flow.  
 * 
 * \param p packet for which we create the bypass
 * \return 1 if the hardware rule was created succesfully, 0 otherwise
*/
int RteFlowBypassCallback(Packet *p)
{
    /* Initial NULL checks and memory allocation */
    SCEnter();
    if ((p == NULL) || (p->flow == NULL)) {
        SCReturnInt(0);
    } 
    Flow *flow = p->flow;
    LiveDevice *livedev = LiveDeviceGetById(flow->livedev_id);
    DPDKDeviceResources *dpdk_vars = LiveDeviceGetById(flow->livedev_id)->dpdk_vars;
    RteFlowBypassData *bypass_data = dpdk_vars->rte_flow_bypass_data;
    FlowBypassInfo *fc = SCFlowGetStorageById(flow, GetFlowBypassInfoID());
    RteFlowHandlerToFlow *flow_handler_info;
    if (fc) {
        if (fc->bypass_data != NULL) {
            SC_ATOMIC_ADD(bypass_data->rte_bypass_mempool_info_get_error, 1);
            SCReturnInt(0);
        }
        if (rte_mempool_get(livedev->dpdk_vars->rte_flow_bypass_data->bypass_info_mp,
                    (void **)&flow_handler_info) < 0) {
            SC_ATOMIC_ADD(bypass_data->rte_bypass_mempool_info_get_error, 1);
            SCReturnInt(0);
        }
    }
    fc->bypass_data = flow_handler_info;

   /* Bypass rules pattern template setup */
    struct rte_flow_item_ipv4 ipv4_spec = { 0 }, ipv4_mask = { 0 };
    struct rte_flow_item_ipv6 ipv6_spec = { 0 }, ipv6_mask = { 0 };
    struct rte_flow_item_tcp tcp_spec = { 0 }, tcp_mask = { 0 };
    struct rte_flow_item_udp udp_spec = { 0 }, udp_mask = { 0 };
    struct rte_flow_item items[] = { { 0 }, { 0 }, { 0 }, { 0 }, { 0 } };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };
    struct rte_flow_action_count count_conf = { 0 };
    struct rte_flow_action count_action = {
        .type = RTE_FLOW_ACTION_TYPE_COUNT,
        .conf = &count_conf
    };
    void *ip_spec = NULL, *ip_mask = NULL, *l4_spec = NULL, *l4_mask = NULL;
    uint16_t L2_INDEX = 0, L3_INDEX = 1, L4_INDEX = 2, END_INDEX = 3;
    uint16_t port_id = dpdk_vars->port_id;
    RteFlowTemplateResources *bypass_resources = NULL;
    uint8_t pattern_template_index = 0;
    uint16_t src_rule_queue_id = 2 * p->dpdk_v.in_queue_id + RTE_SRC_CREATE_RULE_QUEUE_OFFSET;
    uint16_t dst_rule_queue_id = 2 * p->dpdk_v.in_queue_id + RTE_DST_CREATE_RULE_QUEUE_OFFSET;
    // SCLogInfo("queueu id: %d", rule_queue_id);
    items[L2_INDEX].type = RTE_FLOW_ITEM_TYPE_ETH;
    items[END_INDEX].type = RTE_FLOW_ITEM_TYPE_END;

    action[0].type = RTE_FLOW_ACTION_TYPE_INDIRECT;
    action[1].type = RTE_FLOW_ACTION_TYPE_DROP;
    action[2].type = RTE_FLOW_ACTION_TYPE_END;

    if (FLOW_IS_IPV4(flow)) {
        bypass_resources = bypass_data->bypass_resources_ipv4;    
        SCLogDebug("Add an IPv4 rte_flow bypass rule");
        ipv4_spec.hdr.src_addr = flow->src.address.address_un_data32[0];
        ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
        ipv4_spec.hdr.dst_addr = flow->dst.address.address_un_data32[0];
        ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
        ip_spec = &ipv4_spec;
        ip_mask = &ipv4_mask;
        items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV4;
    } else {
//         bypass_resources = bypass_data->bypass_resources_ipv6;
// #if RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0)
//         SCLogDebug("Add an IPv6 rte_flow bypass rule");
//         memcpy(ipv6_spec.hdr.src_addr.a, flow->src.address.address_un_data8, 16);
//         memset(ipv6_mask.hdr.src_addr.a, 0xFF, 16);
//         memcpy(ipv6_spec.hdr.dst_addr.a, flow->dst.address.address_un_data8, 16);
//         memset(ipv6_mask.hdr.dst_addr.a, 0xFF, 16);
// #else
//         SCLogDebug("Add an IPv6 rte_flow bypass rule");
//         memcpy(ipv6_spec.hdr.src_addr, flow->src.address.address_un_data8, 16);
//         memset(ipv6_mask.hdr.src_addr, 0xFF, 16);
//         memcpy(ipv6_spec.hdr.dst_addr, flow->dst.address.address_un_data8, 16);
//         memset(ipv6_mask.hdr.dst_addr, 0xFF, 16);
// #endif /* RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0) */
//         ip_spec = &ipv6_spec;
//         ip_mask = &ipv6_mask;
//         items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV6;
        SCReturnInt(0);
    }

    if (flow->proto == IPPROTO_TCP) {
        pattern_template_index = RTE_PATTERN_TEMPLATE_TCP;
        tcp_spec.hdr.src_port = htons(flow->sp);
        tcp_mask.hdr.src_port = 0xFFFF;
        tcp_spec.hdr.dst_port = htons(flow->dp);
        tcp_mask.hdr.dst_port = 0xFFFF;
        l4_spec = &tcp_spec;
        l4_mask = &tcp_mask;
        items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_TCP;
    } else {
        pattern_template_index = RTE_PATTERN_TEMPLATE_UDP;
        udp_spec.hdr.src_port = htons(flow->sp);
        udp_mask.hdr.src_port = 0xFFFF;
        udp_spec.hdr.dst_port = htons(flow->dp);
        udp_mask.hdr.dst_port = 0xFFFF;
        l4_spec = &udp_spec;
        l4_mask = &udp_mask;
        items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_UDP;
    }

    items[L3_INDEX].spec = ip_spec;
    items[L3_INDEX].mask = ip_mask;
    items[L4_INDEX].spec = l4_spec;
    items[L4_INDEX].mask = l4_mask;
	
    struct rte_flow_action_handle *src_action_handle = RteFlowCreateIndirectAction(port_id, src_rule_queue_id, &count_action);
    action[0].conf = src_action_handle;
    struct rte_flow *src_rule_handler = RteFlowCreateRuleAsync(dpdk_vars->port_id, src_rule_queue_id, bypass_resources->tbl, items, pattern_template_index, action, RTE_ACTIONS_TEMPLATE_DEFAULT, fc->bypass_data);

    /* Create rte_flow rule for the opposite direction */
    if (FLOW_IS_IPV4(flow)) {
        SCLogDebug("Add an IPv4 rte_flow bypass rule in other direction");
        ipv4_spec.hdr.src_addr = flow->dst.address.address_un_data32[0];
        ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
        ipv4_spec.hdr.dst_addr = flow->src.address.address_un_data32[0];
        ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
        ip_spec = &ipv4_spec;
        ip_mask = &ipv4_mask;
        items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV4;
    } else {
        SCLogDebug("Add an IPv6 rte_flow bypass rule");
#if RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0)
        memcpy(ipv6_spec.hdr.src_addr.a, flow->dst.address.address_un_data8, 16);
        memset(ipv6_mask.hdr.src_addr.a, 0xFF, 16);
        memcpy(ipv6_spec.hdr.dst_addr.a, flow->src.address.address_un_data8, 16);
        memset(ipv6_mask.hdr.dst_addr.a, 0xFF, 16);
#else
        memcpy(ipv6_spec.hdr.src_addr, flow->dst.address.address_un_data8, 16);
        memset(ipv6_mask.hdr.src_addr, 0xFF, 16);
        memcpy(ipv6_spec.hdr.dst_addr, flow->src.address.address_un_data8, 16);
        memset(ipv6_mask.hdr.dst_addr, 0xFF, 16);
#endif /* RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0) */
        ip_spec = &ipv6_spec;
        ip_mask = &ipv6_mask;
        items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV6;
    }

    if (flow->proto == IPPROTO_TCP) {
        tcp_spec.hdr.src_port = htons(flow->dp);
        tcp_mask.hdr.src_port = 0xFFFF;
        tcp_spec.hdr.dst_port = htons(flow->sp);
        tcp_mask.hdr.dst_port = 0xFFFF;
        l4_spec = &tcp_spec;
        l4_mask = &tcp_mask;
        items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_TCP;
    } else {
        udp_spec.hdr.src_port = htons(flow->dp);
        udp_mask.hdr.src_port = 0xFFFF;
        udp_spec.hdr.dst_port = htons(flow->sp);
        udp_mask.hdr.dst_port = 0xFFFF;
        l4_spec = &udp_spec;
        l4_mask = &udp_mask;
        items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_UDP;
    }

    items[L3_INDEX].spec = ip_spec;
    items[L3_INDEX].mask = ip_mask;
    items[L4_INDEX].spec = l4_spec;
    items[L4_INDEX].mask = l4_mask;

    struct rte_flow_action_handle *dst_action_handle = RteFlowCreateIndirectAction(port_id, dst_rule_queue_id, &count_action); 
    action[0].conf = dst_action_handle;
    struct rte_flow *dst_rule_handler = RteFlowCreateRuleAsync(port_id, dst_rule_queue_id, bypass_resources->tbl, items, pattern_template_index, action, RTE_ACTIONS_TEMPLATE_DEFAULT, fc->bypass_data);
    
    if (src_rule_handler == NULL || dst_rule_handler == NULL) {
            RteFlowRuleDestroy(port_id, src_rule_queue_id, src_rule_handler, src_action_handle, flow_handler_info);
            RteFlowRuleDestroy(port_id, dst_rule_queue_id, dst_rule_handler, dst_action_handle, flow_handler_info);
            SC_ATOMIC_ADD(bypass_data->rte_bypass_flows_bypass_error, 1);
            FLOWLOCK_UNLOCK(flow);
            SCReturnInt(0);
    }

    int inet_family = FLOW_IS_IPV4(flow) ? AF_INET : AF_INET6;
    RteFlowSetFlowBypassInfo(fc, flow, src_rule_handler, dst_rule_handler, src_action_handle, dst_action_handle, inet_family);
    flow_handler_info->in_queue_id = p->dpdk_v.in_queue_id;
    SC_ATOMIC_ADD(bypass_data->rte_bypass_rules_active, 2);
    SC_ATOMIC_ADD(bypass_data->rte_bypass_rules_created, 2);
    SC_ATOMIC_ADD(bypass_data->rte_bypass_rules_unchecked, 2);
    SC_ATOMIC_ADD(bypass_data->rte_bypass_flows_bypass_success, 1);
    FLOWLOCK_UNLOCK(flow);
    

    RteFlowWorkerDrain(port_id, p->dpdk_v.in_queue_id, bypass_data);

    SCReturnInt(1);
}
#pragma GCC diagnostic pop

/**
 * @}
 */

#endif /* HAVE_DPDK */
