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
#include "flow-manager.h"
#include "runmode-dpdk.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-ice.h"
#include "util-dpdk-mlx5.h"
#include "util-dpdk-nfb.h"
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

#define L2_INDEX    0
#define VLAN_INDEX  4
#define L3_INDEX    1
#define L4_INDEX    2
#define END_INDEX   3

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static uint32_t RteFlowBypassGetBypassInfoMPSize(const char *, uint32_t *);
static void RteFlowRuleDestroy(uint16_t, RteFlowHandlerToFlow *);
static void RteFlowHandleEmergency(ThreadVars *, Flow *, void *);
static int RteFlowUpdateStats(FlowBypassInfo *, RteFlowHandlerToFlow *);
static int RteFlowCheckRules(ThreadVars *th_v, struct flows_stats *bypassstats, struct timespec *curtime, void *data);
static uint32_t DeviceDecideRteFlowRulesCapacity(const char *);
static int RteFlowBypassBeforeStartInit(uint16_t, const char *, const char *, RteFlowBypassData *);

static uint16_t rte_bypass_manager_queue_id;

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
 * \brief Initialize pattern templates for dynamic bypass rules.
 *
 * Creates pattern templates for IPv4/IPv6 + TCP/UDP combinations for both
 * the ipv4 and ipv6 template resources and stores them in RteFlowBypassData
 * for later use.
 *
 * \param port_id DPDK port identifier
 * \param data bypass data structure to populate
 * \return 0 on success, -1 on error
 */
static int RteFlowTemplatePatternInit(uint16_t port_id, RteFlowBypassData *data)
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
        goto cleanup;
    }
    /* Bypass rules pattern template setup */

    bypass_resources_ipv4->pt[RTE_PATTERN_TEMPLATE_TCP_NO_VLAN] = RteFlowCreatePatternTemplate(
            port_id, pattern_template_novlan_ipv4_tcp);

    bypass_resources_ipv4->pt[RTE_PATTERN_TEMPLATE_TCP_VLAN] = RteFlowCreatePatternTemplate(
            port_id, pattern_template_vlan_ipv4_tcp);

    bypass_resources_ipv4->pt[RTE_PATTERN_TEMPLATE_UDP_NO_VLAN] = RteFlowCreatePatternTemplate(
            port_id, pattern_template_novlan_ipv4_udp);

    bypass_resources_ipv4->pt[RTE_PATTERN_TEMPLATE_UDP_VLAN] = RteFlowCreatePatternTemplate(
            port_id, pattern_template_vlan_ipv4_udp);

    bypass_resources_ipv6->pt[RTE_PATTERN_TEMPLATE_TCP_NO_VLAN] = RteFlowCreatePatternTemplate(
            port_id, pattern_template_novlan_ipv6_tcp);

    bypass_resources_ipv6->pt[RTE_PATTERN_TEMPLATE_TCP_VLAN] = RteFlowCreatePatternTemplate(
            port_id, pattern_template_vlan_ipv6_tcp);

    bypass_resources_ipv6->pt[RTE_PATTERN_TEMPLATE_UDP_NO_VLAN] = RteFlowCreatePatternTemplate(
            port_id, pattern_template_novlan_ipv6_udp);

    bypass_resources_ipv6->pt[RTE_PATTERN_TEMPLATE_UDP_VLAN] = RteFlowCreatePatternTemplate(
            port_id, pattern_template_vlan_ipv6_udp);

    bypass_resources_ipv4->pt_cnt = 4;
    bypass_resources_ipv6->pt_cnt = 4;
    for (int i = 0; i < bypass_resources_ipv4->pt_cnt; i++) {
        if (bypass_resources_ipv4->pt[i] == NULL || bypass_resources_ipv6->pt[i] == NULL) {
            SCLogError("rte_flow_bypas: pattern_template %d is null", i);
            goto cleanup;
        }
    }

    data->bypass_resources_ipv4 = bypass_resources_ipv4;
    data->bypass_resources_ipv6 = bypass_resources_ipv6;
    SCReturnInt(0);

cleanup:
    SCLogError("rte_flow_bypass: bypass pattern template failed");
    RteFlowBypasTemplateResourcesFree(port_id, bypass_resources_ipv4);
    RteFlowBypasTemplateResourcesFree(port_id, bypass_resources_ipv6);
    data->bypass_resources_ipv4 = NULL;
    data->bypass_resources_ipv6 = NULL;
    SCReturnInt(-1);
}

/**
 * \brief Initialize actions templates for dynamic bypass rules.
 *
 * Creates actions templates for both the ipv4 and ipv6 template resources and
 * stores them in RteFlowBypassData for later use.
 *
 * \param port_id DPDK port identifier
 * \param data bypass data structure to populate
 * \return 0 on success, -1 on error
 */
static int RteFlowTemplateActionsInit(uint16_t port_id, RteFlowBypassData *data)
{
    SCEnter();
    RteFlowTemplateResources *bypass_resources_ipv4 = data->bypass_resources_ipv4;
    RteFlowTemplateResources *bypass_resources_ipv6 = data->bypass_resources_ipv6;
    if (bypass_resources_ipv4 == NULL || bypass_resources_ipv6 == NULL) {
        SCLogError("rte_flow dynamic bypass: template resources not initialized");
        SCReturnInt(-1);
    }

    /* Bypass rules actions template setup */
    struct rte_flow_action actions_template[] = {
        [0] = { .type = RTE_FLOW_ACTION_TYPE_INDIRECT_LIST },
        [1] = { .type = RTE_FLOW_ACTION_TYPE_DROP },
        [2] = { .type = RTE_FLOW_ACTION_TYPE_END },
    };
    struct rte_flow_action actions_masks_template[] = {
        [0] = { .type = RTE_FLOW_ACTION_TYPE_INDIRECT_LIST },
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

    SCReturnInt(0);

cleanup:
    SCLogError("rte_flow_bypass: bypass actions template failed");
    RteFlowBypasTemplateResourcesFree(port_id, bypass_resources_ipv4);
    RteFlowBypasTemplateResourcesFree(port_id, bypass_resources_ipv6);
    data->bypass_resources_ipv4 = NULL;
    data->bypass_resources_ipv6 = NULL;
    SCReturnInt(-1);
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
int RteFlowBypassTemplateResourcesInit(uint16_t port_id, RteFlowBypassData *data)
{
    SCEnter();
    if (RteFlowTemplatePatternInit(port_id, data) != 0) {
        SCReturnInt(-1);
    }
    if (RteFlowTemplateActionsInit(port_id, data) != 0) {
        SCReturnInt(-1);
    }

    RteFlowTemplateResources *bypass_resources_ipv4 = data->bypass_resources_ipv4;
    RteFlowTemplateResources *bypass_resources_ipv6 = data->bypass_resources_ipv6;

    /* Bypass rules template table setup */
    bypass_resources_ipv4->tbl = RteFlowCreateTemplateTable(
            port_id, RTE_DEFAULT_GROUP, RTE_RULE_PRIORITY_0, data->bypass_info_mp->size, bypass_resources_ipv4->pt, bypass_resources_ipv4->pt_cnt, &bypass_resources_ipv4->at, 1);
    if (bypass_resources_ipv4->tbl == NULL) {
        goto cleanup;
    }
   bypass_resources_ipv6->tbl = RteFlowCreateTemplateTable(
            port_id, RTE_DEFAULT_GROUP, RTE_RULE_PRIORITY_0, data->bypass_info_mp->size, bypass_resources_ipv6->pt, bypass_resources_ipv6->pt_cnt, &bypass_resources_ipv6->at, 1);
    if (bypass_resources_ipv6->tbl == NULL) {
        goto cleanup;
    }

    SCReturnInt(0);

cleanup:
    SCLogError("rte_flow_bypass: bypass template failed");
    RteFlowBypasTemplateResourcesFree(port_id, bypass_resources_ipv4);
    RteFlowBypasTemplateResourcesFree(port_id, bypass_resources_ipv6);
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
void RteFlowBypasTemplateResourcesFree(uint16_t port_id, RteFlowTemplateResources *template_resources)
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
RteFlowCreatePatternTemplate(int port_id, const struct rte_flow_item *pattern)
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
 * \brief Initialize the async jump rule (group 0 -> group 1).
 * \param data bypass data structure to populate with jump rule handles
 * \param port_id DPDK port identifier
 * \return 0 on success, -1 on error
 */
int RteFlowJumpRuleTemplateInit(uint16_t port_id, RteFlowBypassData *data)
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
    RteFlowBypasTemplateResourcesFree(port_id, data->jump_resources);
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

static int RteFlowBypassBeforeStartInit(uint16_t port_id, const char *driver_name, const char *port_name, RteFlowBypassData *rte_flow_bypass_data)
{
    uint32_t nb_flowmgr = 1;

    rte_flow_bypass_data->nb_flow_manager_queues = nb_flowmgr;
    rte_flow_bypass_data->rte_flow_manager_queue_base = rte_flow_bypass_data->nb_rx_queues + 1;
    rte_bypass_manager_queue_id = rte_flow_bypass_data->nb_rx_queues;

    uint16_t rte_flow_async_queues = (uint16_t)(rte_flow_bypass_data->nb_rx_queues + 1 + nb_flowmgr);

    int retval = rte_flow_bypass_data->RteFlowDeviceTemplatesInit(port_id, rte_flow_async_queues, port_name, rte_flow_bypass_data);
    
    SCReturnInt(retval);
}

static void RteFlowBypassRegisterCallbacks(const char *driver_name, RteFlowBypassData *bypass_data)
{
    if (strcmp(driver_name, "mlx5_pci") == 0) {
        bypass_data->RteFlowDeviceBypassCallback = mlx5DeviceRteFlowBypassCallback;
        bypass_data->RteFlowDeviceBypassUpdateStats = mlx5DeviceRteFlowUpdateStats;
        bypass_data->RteFlowDeviceDestroyRule = mlx5DeviceRteFlowRuleDestroy;
        bypass_data->RteFlowDeviceTemplatesInit = mlx5DeviceRteFlowTemplatesInit;
    }

    if (strcmp(driver_name, "net_nfb") == 0) {
        bypass_data->RteFlowDeviceBypassCallback = nfbDeviceRteFlowBypassCallback;
        bypass_data->RteFlowDeviceBypassUpdateStats = nfbDeviceRteFlowUpdateStats;
        bypass_data->RteFlowDeviceDestroyRule = nfbDeviceRteFlowRuleDestroy;
        bypass_data->RteFlowDeviceTemplatesInit = nfbDeviceRteFlowTemplatesInit;
    }
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

    RteFlowBypassRegisterCallbacks(driver_name, rte_flow_bypass_data);

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
    strlcpy(rte_flow_bypass_data->drive_name, driver_name, sizeof(driver_name));

    retval = RteFlowBypassBeforeStartInit(iconf->port_id, driver_name, port_name, rte_flow_bypass_data);
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
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_pkts);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_bytes);

    iconf->dpdk_dev_resources->rte_flow_bypass_data = rte_flow_bypass_data;

    SCReturnInt(retval);

cleanup:
    RteFlowBypasTemplateResourcesFree(iconf->port_id, rte_flow_bypass_data->bypass_resources_ipv4);
    RteFlowBypasTemplateResourcesFree(iconf->port_id, rte_flow_bypass_data->bypass_resources_ipv6);
    SCFree(rte_flow_bypass_data);
    SCReturnInt(retval);
}

static int RteFlowCheckRules(ThreadVars *th_v, struct flows_stats *bypassstats, struct timespec *curtime, void *data)
{
    RteFlowBypassData *bypass_data = (RteFlowBypassData *) data;
    if (bypass_data == NULL) {
        SCReturnInt(0);
    }

    int pull_cnt;
    const int max_res_size = 1024;
    struct rte_flow_op_result res[max_res_size];
    struct rte_flow_error flow_error = { 0 };
    for (uint16_t q_id = 0; q_id < bypass_data->nb_rx_queues; q_id++) {
        do {
            pull_cnt = rte_flow_pull(bypass_data->port_id, q_id, res, max_res_size, &flow_error);
            if (pull_cnt < 0) {
                SCLogWarning("rte_flow bypass: worker pull failed on queue %u: %s",
                        q_id, flow_error.message);
                break;
            }
            for (int i = 0; i < pull_cnt; i++) {
                if (res[i].status != 0 && res[i].user_data != NULL) {
                    RteFlowHandlerToFlow *flow_handler_info =
                            (RteFlowHandlerToFlow *)res[i].user_data;
                    SCLogInfo("Incorrect rule");
                    FLOWLOCK_WRLOCK(flow_handler_info->flow);
                    FlowUpdateState(flow_handler_info->flow, FLOW_STATE_LOCAL_BYPASSED);
                    FLOWLOCK_UNLOCK(flow_handler_info->flow);
                    SC_ATOMIC_ADD(bypass_data->rte_bypass_flows_bypass_error, 1);
                }
            }
        } while (pull_cnt == max_res_size);
    }

    if (bypassstats != NULL) {
        bypassstats->count = SC_ATOMIC_GET(bypass_data->rte_bypass_rules_active);
    }
    SCReturnInt(1);
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
static int RteFlowUpdateStats(FlowBypassInfo *fc, RteFlowHandlerToFlow *flow_handler_info)
{
    uint64_t old_src_pkts = flow_handler_info->count_src.hits;
    uint64_t old_dst_pkts = flow_handler_info->count_dst.hits;
    RteFlowBypassData *bypass_data = flow_handler_info->rte_flow_bypass_data;

    flow_handler_info->rte_flow_bypass_data->RteFlowDeviceBypassUpdateStats(bypass_data->rte_flow_manager_queue_base, flow_handler_info);

    if (flow_handler_info->count_src.hits > old_src_pkts || flow_handler_info->count_dst.hits > old_dst_pkts) {
        fc->tosrcpktcnt += flow_handler_info->count_src.hits;
        fc->tosrcbytecnt += flow_handler_info->count_src.bytes;
        fc->todstpktcnt +=  flow_handler_info->count_dst.hits;
        fc->todstbytecnt += flow_handler_info->count_dst.bytes;
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
static void RteFlowRuleDestroy(uint16_t queue_id, RteFlowHandlerToFlow *flow_handler_info)
{
    RteFlowBypassData *bypass_data = flow_handler_info->rte_flow_bypass_data;
    bypass_data->RteFlowDeviceDestroyRule(queue_id, flow_handler_info);
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
    if (flow_handler_info->src_handle == NULL ) {//| flow_handler_info->dst_handle == NULL) {
        /* Rules already deleted */
        return false;
    }
    LiveDevice *livedev = LiveDeviceGetById(flow->livedev_id);
    RteFlowBypassData *bypass_data = livedev->dpdk_vars->rte_flow_bypass_data;
    bool activity = RteFlowUpdateStats(fc, flow_handler_info);

    if (activity) {
        /* The query returns cumulative HW counters. Accumulate the delta since
         * the last call so both this flow's fc counters and the aggregate
         * bypass counters keep growing monotonically. */
        uint64_t dpkts = flow_handler_info->count_src.hits > fc->tosrcpktcnt ?
                flow_handler_info->count_src.hits - fc->tosrcpktcnt : 0;
        uint64_t dbytes = flow_handler_info->count_src.bytes > fc->tosrcbytecnt ?
                flow_handler_info->count_src.bytes - fc->tosrcbytecnt : 0;
        uint64_t dcpkts = flow_handler_info->count_dst.hits > fc->todstpktcnt ?
                flow_handler_info->count_dst.hits - fc->todstpktcnt : 0;
        uint64_t dcbytes = flow_handler_info->count_dst.bytes > fc->todstbytecnt ?
                flow_handler_info->count_dst.bytes - fc->todstbytecnt : 0;

        fc->tosrcpktcnt = flow_handler_info->count_src.hits;
        fc->tosrcbytecnt = flow_handler_info->count_src.bytes;
        fc->todstpktcnt = flow_handler_info->count_dst.hits;
        fc->todstbytecnt = flow_handler_info->count_dst.bytes;
        flow->lastts = SCTIME_FROM_SECS(tsec);

        if (bypass_data != NULL) {
            SC_ATOMIC_ADD(bypass_data->rte_bypass_pkts, dpkts + dcpkts);
            SC_ATOMIC_ADD(bypass_data->rte_bypass_bytes, dbytes + dcbytes);
        }
    }
    /* At shutdown, we only get the counters. We delete the rules with rte_flow_flush later */
    if (unlikely(suricata_ctl_flags != 0)) {
        flow_handler_info->src_handle = NULL;
        flow_handler_info->dst_handle = NULL;
        SC_ATOMIC_SUB(bypass_data->rte_bypass_rules_active, 2);
        return activity;
    }

    if (!activity) {
        if (flow_handler_info->src_handle != NULL) { //&& flow_handler_info->dst_handle != NULL) {
            RteFlowRuleDestroy(0, flow_handler_info);
            flow_handler_info->src_handle = NULL;
            flow_handler_info->dst_handle = NULL;
            SC_ATOMIC_SUB(bypass_data->rte_bypass_rules_active, 2);
        }
    }
    SCReturnBool(activity);
}

void RteFlowSetFlowBypassInfo(FlowBypassInfo *fc,
        Flow *flow, struct rte_flow *src_handler, struct rte_flow *dst_handler, struct rte_flow_action_list_handle *src_action_list_handle, struct rte_flow_action_list_handle *dst_action_list_handle, int family)
{
    LiveDevice *livedev = LiveDeviceGetById(flow->livedev_id);
    RteFlowHandlerToFlow *flow_handler_info = (RteFlowHandlerToFlow *)fc->bypass_data;

    flow_handler_info->flow = flow;
    flow_handler_info->src_handle = src_handler;
    flow_handler_info->src_action_list_handle = src_action_list_handle;
    flow_handler_info->dst_handle = dst_handler;
    flow_handler_info->dst_action_list_handle = dst_action_list_handle;
    flow_handler_info->livedev_id = livedev->id;

	memset(&flow_handler_info->conntrack, 0, sizeof(flow_handler_info->conntrack));
	memset(&flow_handler_info->count_src, 0, sizeof(flow_handler_info->count_src));
	memset(&flow_handler_info->count_dst, 0, sizeof(flow_handler_info->count_dst));

    flow_handler_info->query[0] = &flow_handler_info->conntrack;
    flow_handler_info->query[1] = &flow_handler_info->count_src;
    flow_handler_info->query[2] = &flow_handler_info->count_dst;

    fc->bypass_data = flow_handler_info;
    fc->BypassUpdate = RteBypassUpdate;
    fc->BypassFree = RteBypassFree;
}

enum RteTemplatePatterns RteGetTemplatePatternIndex(bool has_vlan, bool is_tcp)
{
    return (has_vlan ? 0 : 1) + (is_tcp ? 0 : 2);
}

/** \brief Call device specific callback for creating the hardware (rte_flow) for the incoming flow.  
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

    DPDKDeviceResources  *dpdk_vars = LiveDeviceGetById(p->flow->livedev_id)->dpdk_vars;
    int retval = dpdk_vars->rte_flow_bypass_data->RteFlowDeviceBypassCallback(p);

    SCReturnInt(retval);
}
#pragma GCC diagnostic pop

/**
 * @}
 */

#endif /* HAVE_DPDK */
