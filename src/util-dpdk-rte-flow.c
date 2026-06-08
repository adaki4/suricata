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

#define RULE_STORAGE_INIT_SIZE 8
#define RULE_STORAGE_SIZE_INC  16
#define COUNT_ACTION_ID        1

// #if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
#define RTE_JUMP_GROUP               1
#define RTE_BYPASS_RING_NAME         "rte_bypass_ring"
#define RTE_BYPASS_MEMPOOL_NAME      "rte_bypass_mempool"
#define RTE_BYPASS_INFO_MEMPOOL_NAME "rte_bypass_info_mempool"
#define RTE_BYPASS_RING_SIZE         65536

static int RteFlowRuleStorageInit(RteFlowRuleStorage *);
static int RteFlowRuleStorageAddRule(RteFlowRuleStorage *, const char *);
static int RteFlowRuleStorageExtendCapacity(RteFlowRuleStorage *, int);
// static char *DriverSpecificErrorMessage(const char *, struct rte_flow_item *);
// static int DeviceCheckDropFilterLimits(RteFlowRuleStorage *, const char *, char **);
// static void RteFlowDropFilterInitAttr(const char *, struct rte_flow_attr *);
// static void RteFlowDropFilterInitAction(
        // RteFlowRuleStorage *, const char *, const char *, struct rte_flow_action *);
static bool RteFlowShouldGatherStats(RteFlowRuleStorage *, const char *, const char *);
static uint32_t RteFlowBypassGetBypassInfoMPSize(const char *, uint32_t *);
static int RteFlowBypassRuleCreate(RteFlowBypassData *, struct rte_flow_item *, int,
        struct rte_flow **, struct rte_flow_action_handle **);
static void RteFlowBiRuleDestroy(RteFlowBypassData *, uint16_t , struct rte_flow *, struct rte_flow *);
static void RteFlowActionHandleDestroyFlow(RteFlowBypassData *, uint16_t,
        struct rte_flow_action_handle *);
static void RteFlowHandleEmergency(ThreadVars *, Flow *, void *);
static int RteFlowUpdateStats(FlowBypassInfo *, uint16_t, struct rte_flow *, struct rte_flow *);
static int RteFlowSetFlowBypassInfo(Flow *, struct rte_flow *, struct rte_flow *,
        struct rte_flow_action_handle *, struct rte_flow_action_handle *, int);
static uint32_t DeviceDecideRteFlowRulesCapacity(const char *, uint32_t);


typedef struct RteFlowHandlerToFlow_ {
    Flow *flow;
    struct rte_flow *src_handler;
    struct rte_flow *dst_handler;
    struct rte_flow_action_handle *src_action_handle;
    struct rte_flow_action_handle *dst_action_handle;
    RteFlowBypassData *rte_flow_bypass_data;
    LiveDevice *livedev;
} RteFlowHandlerToFlow;

/* ========================================================================
 * DROP-FILTER FUNCTIONS — commented out during Template API migration.
 * These functions used the classic rte_flow API for static drop-filter
 * rules loaded from suricata.yaml. They are no longer needed.
 * ======================================================================== */
#if 0

/**
 * \brief Specify ambiguous error messages as some drivers have specific
 *        behaviour when creating rte_flow rules.
 *
 * \param driver_name name of a driver
 * \param items array of pattern items
 * \return error message if error present, NULL otherwise
 */
static char *DriverSpecificErrorMessage(const char *driver_name, struct rte_flow_item *items)
{
    if (strcmp(driver_name, "net_ice") == 0) {
        if (iceDeviceRteFlowPatternError(items) == true) {
            char msg[] = "Driver specific errmsg: ice driver does not support broad patterns";
            char *ret = SCCalloc((strlen(msg) + 1), sizeof(msg[0]));
            strlcpy(ret, msg, sizeof(msg[0]) * (strlen(msg) + 1));
            return ret;
        }
    }
    return NULL;
}

static int DeviceCheckDropFilterLimits(
        RteFlowRuleStorage *rule_storage, const char *driver_name, char **err_msg)
{
    if (strcmp(driver_name, "mlx5_pci") == 0)
        return mlx5DeviceCheckDropFilterLimits(rule_storage->rule_cnt, err_msg);
    return 0;
}

static void RteFlowDropFilterInitJumpRule(uint16_t port_id)
{
    struct rte_flow_error flow_error = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_item pattern[] = { { 0 } };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };

    uint32_t jump_group = RTE_JUMP_GROUP;

    attr.ingress = 1;
    attr.priority = 0;
    attr.group = 0;

    pattern[0].type = RTE_FLOW_ITEM_TYPE_END;

    struct rte_flow_action_jump jump = {
        .group = jump_group,
    };
    action[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
    action[0].conf = &jump;

    struct rte_flow *flow_handler = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow_handler == NULL) {
        SCLogError("Error when creating rte_flow jump rule  %s", flow_error.message);
    }
}

/**
 * \brief Initializes the attributes of rte_flow rules
 *
 * \param driver_name name of the driver
 * \param[out] attr attributes which configure how the rte_flow rules will behave
 */
static void RteFlowDropFilterInitAttr(const char *driver_name, struct rte_flow_attr *attr)
{
    attr->ingress = 1;
    attr->priority = 0;
    attr->group = RTE_JUMP_GROUP;

    /* ICE PMD has to have attribute group set to 2 on DPDK 23.11 and higher for the count action to
     * work properly */
    if (strcmp(driver_name, "net_ice") == 0) {
#if RTE_VERSION >= RTE_VERSION_NUM(23, 11, 0, 0)
        attr->group = 2;
#endif /* RTE_VERSION >= RTE_VERSION_NUM(23, 11, 0, 0) */
    }
}

/**
 * \brief Configures the action which will rte_flow rules perform and
 *        decides whether statistic will be gathered or not
 *
 * \param rule_storage struct contaning number of rules and their string instances
 * \param port_name name of the port
 * \param driver_name name of the driver
 * \param[out] action types of actions to be used in the rte_flow rules
 */
static void RteFlowDropFilterInitAction(RteFlowRuleStorage *rule_storage, const char *port_name,
        const char *driver_name, struct rte_flow_action *action)
{
    /* ICE PMD does not support count action with wildcard pattern (mask and last pattern item
     * types). The count action is omitted when wildcard pattern is detected */
    if (strcmp(driver_name, "net_ice") == 0 &&
            !iceDeviceDecideRteFlowActionType(rule_storage, port_name)) {
        action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
        action[1].type = RTE_FLOW_ACTION_TYPE_END;
        return;
    }
    if (strcmp(driver_name, "net_ice") == 0 || strcmp(driver_name, "mlx5_pci") == 0) {
        action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
        static uint32_t counter_id = COUNT_ACTION_ID;
        action[0].conf = &counter_id;
        action[1].type = RTE_FLOW_ACTION_TYPE_DROP;
        action[2].type = RTE_FLOW_ACTION_TYPE_END;
        return;
    }
    action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;
    return;
}

/**
 * \brief Function decides, based on the driver and type of rte_flow rules,
 *        whether to gather statistics with counter in rte_flow rules or no.
 *
 * \param rule_storage rules loaded from suricata.yam
 * \param driver_name name of the driver
 * \param port_name name of the port
 * \return true if gathering stats from rte_flow rules is possible, false otherwise
 */
static bool RteFlowShouldGatherStats(
        RteFlowRuleStorage *rule_storage, const char *driver_name, const char *port_name)
{
    if (strcmp(driver_name, "net_ice") == 0 &&
            !iceDeviceDecideRteFlowActionType(rule_storage, port_name))
        return false;
    return true;
}
// #endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0) */
#endif 0

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
/**
 * \brief Initialize Template API resources for dynamic bypass rules.
 *
 * Creates a single template table with relaxed matching that supports
 * IPv4/IPv6 + TCP/UDP combinations. The pattern template, actions template,
 * and template table are stored in RteFlowBypassData for later use.
 *
 * \param data      bypass data structure to populate
 * \param port_id   DPDK port identifier
 * \return 0 on success, -1 on error
 */
int RteFlowTemplateResourcesInit(RteFlowBypassData *data, uint16_t port_id)
{
    struct rte_flow_error flow_error = { 0 };
    struct rte_flow_attr attr = {
        .ingress = 1,
        .priority = 0,
        .group = 1,
        .transfer = 0,
    };

    /* --- Pattern Template (relaxed matching for IPv4/IPv6 + TCP/UDP) --- */
    struct rte_flow_item pattern_template[] = {
        [0] = { .type = RTE_FLOW_ITEM_TYPE_ETH },
        [1] = { .type = RTE_FLOW_ITEM_TYPE_IPV4 },
        [2] = { .type = RTE_FLOW_ITEM_TYPE_TCP },
        [3] = { .type = RTE_FLOW_ITEM_TYPE_END },
    };

    struct rte_flow_pattern_template_attr pt_attr = {
        .relaxed_matching = 0,
        .ingress = 1,
    };

    data->bypass_pt = rte_flow_pattern_template_create(
            port_id, &pt_attr, pattern_template, &flow_error);
    if (data->bypass_pt == NULL) {
        SCLogError("rte_flow dynamic bypass: pattern template create error: %s",
                flow_error.message);
        return -1;
    }

    /* --- Actions Template (INDIRECT COUNT + DROP) --- */
    /* Match conntrack-example.c: actions are INDIRECT (per-flow handle) +
     * DROP. The mask uses COUNT so the PMD knows this slot is a counter
     * action that will be bound to a per-flow indirect handle at rule
     * creation time. */
    struct rte_flow_action_count count_conf = { 0 };
    struct rte_flow_action actions_template[] = {
        [0] = { .type = RTE_FLOW_ACTION_TYPE_INDIRECT },
        [1] = { .type = RTE_FLOW_ACTION_TYPE_DROP },
        [2] = { .type = RTE_FLOW_ACTION_TYPE_END },
    };

    struct rte_flow_action masks_template[] = {
        [0] = { .type = RTE_FLOW_ACTION_TYPE_COUNT,
                .conf = &count_conf },
        [1] = { .type = RTE_FLOW_ACTION_TYPE_DROP },
        [2] = { .type = RTE_FLOW_ACTION_TYPE_END },
    };

    struct rte_flow_actions_template_attr at_attr = {
        .ingress = 1,
    };

    data->bypass_at = rte_flow_actions_template_create(
            port_id, &at_attr, actions_template, masks_template, &flow_error);
    if (data->bypass_at == NULL) {
        SCLogError("rte_flow dynamic bypass: actions template create error: %s",
                flow_error.message);
        rte_flow_pattern_template_destroy(port_id, data->bypass_pt, &flow_error);
        data->bypass_pt = NULL;
        return -1;
    }

    /* --- Template Table --- */
    struct rte_flow_template_table_attr tbl_attr = {
        .flow_attr = attr,
        .nb_flows = data->rte_bypass_rule_capacity,
    };

    data->bypass_tbl = rte_flow_template_table_create(
            port_id, &tbl_attr, &data->bypass_pt, 1, &data->bypass_at, 1, &flow_error);
    if (data->bypass_tbl == NULL) {
        SCLogError("rte_flow dynamic bypass: template table create error: %s",
                flow_error.message);
        rte_flow_actions_template_destroy(port_id, data->bypass_at, &flow_error);
        rte_flow_pattern_template_destroy(port_id, data->bypass_pt, &flow_error);
        data->bypass_at = NULL;
        data->bypass_pt = NULL;
        return -1;
    }

    data->op_attr.postpone = 0;
    data->port_id = port_id;
    data->template_api_available = true;

    SCLogInfo("rte_flow dynamic bypass: Template API resources initialized (capacity: %u)",
            data->rte_bypass_rule_capacity);
    return 0;
}

/**
 * \brief Free Template API resources for dynamic bypass rules.
 *
 * \param data bypass data structure containing template handles
 */
void RteFlowTemplateResourcesFree(RteFlowBypassData *data)
{
    struct rte_flow_error flow_error = { 0 };

    /* Free jump rule (classic API handle) first */
    RteFlowJumpRuleFree(data);

    if (data->bypass_tbl != NULL) {
        rte_flow_template_table_destroy(data->port_id, data->bypass_tbl, &flow_error);
        data->bypass_tbl = NULL;
    }
    if (data->bypass_at != NULL) {
        rte_flow_actions_template_destroy(data->port_id, data->bypass_at, &flow_error);
        data->bypass_at = NULL;
    }
    if (data->bypass_pt != NULL) {
        rte_flow_pattern_template_destroy(data->port_id, data->bypass_pt, &flow_error);
        data->bypass_pt = NULL;
    }
    data->template_api_available = false;
}

/**
 * \brief Initialize async jump rule (group 0 -> group 1) using Template API.
 *
 * Creates a match-all pattern template, a JUMP actions template targeting
 * RTE_JUMP_GROUP, a template table in group 0, and an async flow rule
 * that redirects all traffic from group 0 to group 1.
 * \
 * Requires data->op_attr and data->port_id to be initialized before calling.
 * Must be called AFTER rte_flow_configure() but BEFORE any group 1 template
 * tables are created (mlx5 PMD requires group 0 tables inserted first).
 * \
 * \param data bypass data structure to populate with jump rule handles
 * \return 0 on success, -1 on error
 */
int RteFlowJumpRuleTemplateInit(RteFlowBypassData *data)
{
    struct rte_flow_error flow_error = { 0 };

    /* The group-0 -> group-1 jump rule uses the async Template API (the
     * classic rte_flow_create is rejected with "Flow non-Q creation not
     * supported" once rte_flow_configure() switches the port to HWS mode).
     *
     * Mirrors conntrack-example.c's setup_rule_templates_jump() /
     * create_rule_jump(): a concrete ETH/IPv4/TCP pattern template, an
     * actions template of INDIRECT(count) + JUMP with a COUNT + JUMP mask,
     * and a rule created with an async per-rule COUNT action handle. The
     * INDIRECT action is essential: with a lone JUMP the mlx5 HWS root-table
     * path leaves rule_acts[0].action NULL (root_action never allocated for
     * root groups) and segfaults in mlx5dr_action_root_build_attr; pairing
     * it with the INDIRECT count populates rule_acts correctly. */

    /* --- Pattern Template (ETH/IPv4/TCP, wildcarded) --- */
    struct rte_flow_item pattern_template[] = {
        [0] = { .type = RTE_FLOW_ITEM_TYPE_ETH },
        [1] = { .type = RTE_FLOW_ITEM_TYPE_IPV4 },
        [2] = { .type = RTE_FLOW_ITEM_TYPE_TCP },
        [3] = { .type = RTE_FLOW_ITEM_TYPE_END },
    };

    struct rte_flow_pattern_template_attr pt_attr = {
        .ingress = 1,
    };

    data->jump_pt = rte_flow_pattern_template_create(
            data->port_id, &pt_attr, pattern_template, &flow_error);
    if (data->jump_pt == NULL) {
        SCLogError("rte_flow jump rule: pattern template create error: %s",
                flow_error.message);
        return -1;
    }

    /* --- Actions Template (INDIRECT count + JUMP), mask (COUNT + JUMP) --- */
    struct rte_flow_action_jump jump_conf = {
        .group = RTE_JUMP_GROUP,
    };
    struct rte_flow_action_jump jump_conf_mask = {
        .group = UINT32_MAX,
    };
    struct rte_flow_action_count count_conf = { 0 };

    struct rte_flow_action actions_template[3] = {
        [0] = { .type = RTE_FLOW_ACTION_TYPE_INDIRECT },
        [1] = { .type = RTE_FLOW_ACTION_TYPE_JUMP, .conf = &jump_conf },
        [2] = { .type = RTE_FLOW_ACTION_TYPE_END },
    };
    struct rte_flow_action masks_template[3] = {
        [0] = { .type = RTE_FLOW_ACTION_TYPE_COUNT, .conf = &count_conf },
        [1] = { .type = RTE_FLOW_ACTION_TYPE_JUMP, .conf = &jump_conf_mask },
        [2] = { .type = RTE_FLOW_ACTION_TYPE_END },
    };

    struct rte_flow_actions_template_attr at_attr = {
        .ingress = 1,
    };

    data->jump_at = rte_flow_actions_template_create(
            data->port_id, &at_attr, actions_template, masks_template, &flow_error);
    if (data->jump_at == NULL) {
        SCLogError("rte_flow jump rule: actions template create error: %s",
                flow_error.message);
        rte_flow_pattern_template_destroy(data->port_id, data->jump_pt, &flow_error);
        data->jump_pt = NULL;
        return -1;
    }

    /* --- Template Table (group 0, single rule) --- */
    struct rte_flow_attr attr = {
        .ingress = 1,
        .priority = 0,
        .group = 0,
    };
    struct rte_flow_template_table_attr tbl_attr = {
        .flow_attr = attr,
        .nb_flows = 1,
    };
    struct rte_flow_pattern_template *pts[] = { data->jump_pt };
    struct rte_flow_actions_template *ats[] = { data->jump_at };

    data->jump_tbl = rte_flow_template_table_create(
            data->port_id, &tbl_attr, pts, RTE_DIM(pts), ats, RTE_DIM(ats), &flow_error);
    if (data->jump_tbl == NULL) {
        SCLogError("rte_flow jump rule: template table create error: %s",
                flow_error.message);
        rte_flow_actions_template_destroy(data->port_id, data->jump_at, &flow_error);
        rte_flow_pattern_template_destroy(data->port_id, data->jump_pt, &flow_error);
        data->jump_at = NULL;
        data->jump_pt = NULL;
        return -1;
    }

    SCLogInfo("rte_flow jump rule: template table created (group 0 -> group %u)", RTE_JUMP_GROUP);
    return 0;
}

int RteFlowJumpRuleInit(RteFlowBypassData *data)
{
    struct rte_flow_error flow_error = { 0 };

    /* The jump-flow rule itself is created AFTER rte_eth_dev_start() (the
     * template table was created earlier by RteFlowJumpRuleTemplateInit). */
    struct rte_flow_action_jump jump_conf = {
        .group = RTE_JUMP_GROUP,
    };

    /* --- Per-rule indirect COUNT action handle (async) --- */
    struct rte_flow_action_count count_action_conf = { 0 };
    struct rte_flow_action count_action = {
        .type = RTE_FLOW_ACTION_TYPE_COUNT,
        .conf = &count_action_conf,
    };
    struct rte_flow_indir_action_conf indir_conf = {
        .ingress = 1,
        .transfer = 0,
    };
    data->jump_count_handle = rte_flow_async_action_handle_create(data->port_id, 0,
            &data->op_attr, &indir_conf, &count_action, NULL, &flow_error);
    if (data->jump_count_handle == NULL) {
        SCLogError("rte_flow jump rule: async COUNT handle create error: %s",
                flow_error.message);
        rte_flow_template_table_destroy(data->port_id, data->jump_tbl, &flow_error);
        rte_flow_actions_template_destroy(data->port_id, data->jump_at, &flow_error);
        rte_flow_pattern_template_destroy(data->port_id, data->jump_pt, &flow_error);
        data->jump_tbl = NULL;
        data->jump_at = NULL;
        data->jump_pt = NULL;
        return -1;
    }

    /* --- Create async jump flow (INDIRECT count + JUMP) --- */
    struct rte_flow_item items[] = {
        [0] = { .type = RTE_FLOW_ITEM_TYPE_ETH },
        [1] = { .type = RTE_FLOW_ITEM_TYPE_IPV4 },
        [2] = { .type = RTE_FLOW_ITEM_TYPE_TCP },
        [3] = { .type = RTE_FLOW_ITEM_TYPE_END },
    };
    struct rte_flow_action actions[3] = {
        [0] = { .type = RTE_FLOW_ACTION_TYPE_INDIRECT, .conf = data->jump_count_handle },
        [1] = { .type = RTE_FLOW_ACTION_TYPE_JUMP, .conf = &jump_conf },
        [2] = { .type = RTE_FLOW_ACTION_TYPE_END },
    };

    data->jump_flow = rte_flow_async_create(
            data->port_id, 0, &data->op_attr,
            data->jump_tbl, items, 0, actions, 0, NULL, &flow_error);
    if (data->jump_flow == NULL) {
        SCLogError("rte_flow jump rule: async create error: %s", flow_error.message);
        rte_flow_async_action_handle_destroy(data->port_id, 0, &data->op_attr,
                data->jump_count_handle, NULL, &flow_error);
        rte_flow_push(data->port_id, 0, &flow_error);
        rte_flow_pull(data->port_id, 0, NULL, 0, &flow_error);
        rte_flow_template_table_destroy(data->port_id, data->jump_tbl, &flow_error);
        rte_flow_actions_template_destroy(data->port_id, data->jump_at, &flow_error);
        rte_flow_pattern_template_destroy(data->port_id, data->jump_pt, &flow_error);
        data->jump_flow = NULL;
        data->jump_count_handle = NULL;
        data->jump_tbl = NULL;
        data->jump_at = NULL;
        data->jump_pt = NULL;
        return -1;
    }

    int retval = rte_flow_push(data->port_id, 0, &flow_error);
    if (retval < 0) {
        SCLogError("rte_flow jump rule: push error: %s", flow_error.message);
        rte_flow_async_destroy(data->port_id, 0, &data->op_attr,
                data->jump_flow, NULL, &flow_error);
        rte_flow_async_action_handle_destroy(data->port_id, 0, &data->op_attr,
                data->jump_count_handle, NULL, &flow_error);
        rte_flow_push(data->port_id, 0, &flow_error);
        rte_flow_pull(data->port_id, 0, NULL, 0, &flow_error);
        rte_flow_template_table_destroy(data->port_id, data->jump_tbl, &flow_error);
        rte_flow_actions_template_destroy(data->port_id, data->jump_at, &flow_error);
        rte_flow_pattern_template_destroy(data->port_id, data->jump_pt, &flow_error);
        data->jump_flow = NULL;
        data->jump_count_handle = NULL;
        data->jump_tbl = NULL;
        data->jump_at = NULL;
        data->jump_pt = NULL;
        return -1;
    }
    rte_flow_pull(data->port_id, 0, NULL, 0, &flow_error);

    SCLogInfo("rte_flow jump rule: async jump rule created (group 0 -> group %u)", RTE_JUMP_GROUP);
    return 0;
}

/**
 * \brief Free the async jump rule (group 0 -> group 1) and its templates.
 *
 * \param data bypass data structure containing the jump rule handles
 */
void RteFlowJumpRuleFree(RteFlowBypassData *data)
{
    struct rte_flow_error flow_error = { 0 };

    if (data->jump_flow != NULL) {
        rte_flow_async_destroy(data->port_id, 0, &data->op_attr,
                data->jump_flow, NULL, &flow_error);
        rte_flow_push(data->port_id, 0, &flow_error);
        rte_flow_pull(data->port_id, 0, NULL, 0, &flow_error);
        data->jump_flow = NULL;
    }
    if (data->jump_count_handle != NULL) {
        rte_flow_async_action_handle_destroy(data->port_id, 0, &data->op_attr,
                data->jump_count_handle, NULL, &flow_error);
        rte_flow_push(data->port_id, 0, &flow_error);
        rte_flow_pull(data->port_id, 0, NULL, 0, &flow_error);
        data->jump_count_handle = NULL;
    }
    if (data->jump_tbl != NULL) {
        rte_flow_template_table_destroy(data->port_id, data->jump_tbl, &flow_error);
        data->jump_tbl = NULL;
    }
    if (data->jump_at != NULL) {
        rte_flow_actions_template_destroy(data->port_id, data->jump_at, &flow_error);
        data->jump_at = NULL;
    }
    if (data->jump_pt != NULL) {
        rte_flow_pattern_template_destroy(data->port_id, data->jump_pt, &flow_error);
        data->jump_pt = NULL;
    }
}
#endif /* RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0) */

#if 0 // no drop-filter


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
    uint32_t max_sz = DeviceDecideRteFlowRulesCapacity(driver_name, 0) - 1;
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
        rte_flow_bypass_data->rte_bypass_rule_capacity -= iconf->drop_filter.rule_cnt;
        SCReturnInt(retval);
    }

    RunModeEnablesBypassManager();
    rte_flow_bypass_data = SCCalloc(1, sizeof(RteFlowBypassData));
    if (rte_flow_bypass_data == NULL) {
        SCLogError("%s: Memory allocation for RteFlowBypassData failed", port_name);
        SCReturnInt(-ENOMEM);
    }

    struct rte_ring *bypass_ring = rte_ring_create(
            RTE_BYPASS_RING_NAME, RTE_BYPASS_RING_SIZE, rte_socket_id(), RING_F_SC_DEQ);
    if (bypass_ring == NULL) {
        SCLogError("%s: rte_ring_create failed with (ring: %s): %s", port_name,
                RTE_BYPASS_RING_NAME, rte_strerror(rte_errno));
        goto cleanup;
    }
    rte_flow_bypass_data->bypass_ring = bypass_ring;

    uint32_t bypass_mempool_size = (RTE_BYPASS_RING_SIZE * 2) - 1;
    struct rte_mempool *bypass_mp = rte_mempool_create(RTE_BYPASS_MEMPOOL_NAME, bypass_mempool_size,
            sizeof(FlowKey), MempoolCacheSizeCalculate(bypass_mempool_size), 0, NULL, NULL, NULL,
            NULL, rte_socket_id(), 0);
    if (bypass_mp == NULL) {
        SCLogError("%s: rte_mempool_create failed (mempool: %s): %s", port_name,
                RTE_BYPASS_MEMPOOL_NAME, rte_strerror(rte_errno));
        goto cleanup;
    }
    rte_flow_bypass_data->bypass_mp = bypass_mp;

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

    BypassedFlowManagerRegisterCheckFunc(RteFlowBypassRuleLoad, NULL, (void *)rte_flow_bypass_data);

    rte_flow_bypass_data->rte_bypass_rule_capacity =
            DeviceDecideRteFlowRulesCapacity(driver_name, iconf->drop_filter.rule_cnt);

    /* Destroys rte_flow rules of bypassed flows evicted during emergency mode */
    SCFlowRegisterFinishCallback(RteFlowHandleEmergency, NULL);

    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_rules_active);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_rules_created);

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
    struct rte_flow_port_attr port_attr = {
        .nb_counters = 1,
    };
    struct rte_flow_queue_attr queue_attr = {
        .size = 64
    };
    const struct rte_flow_queue_attr *queue_attrs[] = {
        &queue_attr,
        &queue_attr,
    };

    struct rte_flow_error flow_error = { 0 };
    retval = rte_flow_configure(
            iconf->port_id, &port_attr, RTE_DIM(queue_attrs), queue_attrs, &flow_error);
    if (retval != 0) {
        SCLogWarning("%s: rte_flow_configure failed: %s, falling back to classic API",
                port_name, flow_error.message);
        /* Continue with classic API — template_api_available remains false.
         * Template API failures are non-fatal: the bypass logic falls back to
         * the classic synchronous rte_flow API (template_api_available == false). */
        retval = 0;
    } else {
        /* Initialize op_attr and port_id BEFORE creating any templates.
         * Both RteFlowJumpRuleInit and RteFlowTemplateResourcesInit depend on these. */
        rte_flow_bypass_data->op_attr.postpone = 0;
        rte_flow_bypass_data->port_id = iconf->port_id;

        /* Initialize Template API resources (group 1 bypass table) and the
         * group-0 jump rule template table. Both template tables are created
         * here (pre-start) because the mlx5 HWS PMD rejects template-table
         * creation after rte_eth_dev_start(). The actual jump FLOW rule is
         * inserted LATER, after rte_eth_dev_start(), by
         * RteFlowBypassPostStartInit() (the mlx5 HWS PMD needs the device
         * started before the root-table JUMP rule can be inserted).
         * Mirrors conntrack-example.c, which creates all template tables
         * before rte_eth_dev_start() and inserts flow rules after it. */
        retval = RteFlowTemplateResourcesInit(rte_flow_bypass_data, iconf->port_id);
        if (retval != 0) {
            SCLogWarning("%s: Template API init failed, falling back to classic rte_flow API",
                    port_name);
            /* Continue with classic API — template_api_available remains false */
            retval = 0;
        } else {
            retval = RteFlowJumpRuleTemplateInit(rte_flow_bypass_data);
            if (retval != 0) {
                SCLogWarning("%s: Jump rule template init failed, "
                             "falling back to classic rte_flow API",
                        port_name);
                RteFlowTemplateResourcesFree(rte_flow_bypass_data);
                /* Continue with classic API — template_api_available remains false */
                retval = 0;
            }
        }
    }
#endif
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_rules_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_enqueue_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_mempool_get_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_info_mempool_get_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_query_error);
    SC_ATOMIC_INIT(rte_flow_bypass_data->rte_bypass_flow_error);

    iconf->dpdk_dev_resources->rte_flow_bypass_data = rte_flow_bypass_data;

    SCReturnInt(retval);

cleanup:
    SCFree(rte_flow_bypass_data);
    SCReturnInt(retval);
}

/**
 * \brief Create the group-0 -> group-1 jump rule AFTER the device has started.
 *
 * The mlx5 HWS PMD requires the Ethernet device to be started
 * (rte_eth_dev_start) before the root-table (group 0) JUMP rule can be
 * inserted — before that, rte_flow_create returns "Flow non-Q creation not
 * supported" and the async root-table path leaves the JUMP root_action NULL
 * (segfault). This mirrors conntrack-example.c, which calls
 * rte_eth_dev_start() before creating any flow rules.
 *
 * Must be called from the last worker thread (the one that performed
 * rte_eth_dev_start) when template_api_available is true. On failure the
 * Template API resources are freed and the bypass logic falls back to the
 * classic rte_flow API.
 *
 * \param rte_flow_bypass_data bypass data (from livedev->dpdk_vars)
 * \return 0 on success (or when bypass/template API is unavailable), negative on error
 */
int RteFlowBypassPostStartInit(RteFlowBypassData *rte_flow_bypass_data)
{
    SCEnter();
    if (rte_flow_bypass_data == NULL || !rte_flow_bypass_data->template_api_available) {
        SCReturnInt(0);
    }
    int retval = RteFlowJumpRuleInit(rte_flow_bypass_data);
    if (retval != 0) {
        SCLogWarning("rte_flow dynamic bypass: jump rule init failed after device "
                     "start, falling back to classic rte_flow API");
        RteFlowTemplateResourcesFree(rte_flow_bypass_data);
        /* template_api_available is now false -> classic API used */
        retval = 0;
    }
    SCReturnInt(retval);
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
static int RteFlowUpdateStats(FlowBypassInfo *fc, uint16_t port_id,
        struct rte_flow *src_rule_handler, struct rte_flow *dst_rule_handler)
{
    SCEnter();
    struct rte_flow_query_count query_count = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };
    struct rte_flow_error flow_error = { 0 };
    uint32_t counter_id = COUNT_ACTION_ID;
    RteFlowHandlerToFlow *flow_handler_info = (RteFlowHandlerToFlow *)fc->bypass_data;
    int retval = 0;

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
    if (flow_handler_info->rte_flow_bypass_data->template_api_available) {
        /* Use rte_flow_async_action_handle_query() on indirect COUNT action handles */
        query_count.reset = 1;

        if (flow_handler_info->src_action_handle != NULL) {
            retval = rte_flow_async_action_handle_query(port_id, 0,
                    &flow_handler_info->rte_flow_bypass_data->op_attr,
                    flow_handler_info->src_action_handle,
                    (void *)&query_count, NULL, &flow_error);
            rte_flow_push(port_id, 0, &flow_error);
            rte_flow_pull(port_id, 0, NULL, 0, &flow_error);
            if (retval != 0) {
                SCLogError("rte_flow dynamic bypass: action handle query error %s errmsg: %s",
                        rte_strerror(-retval), flow_error.message);
                SC_ATOMIC_ADD(flow_handler_info->rte_flow_bypass_data->rte_bypass_query_error, 1);
            }
        }

        uint32_t src_packets = query_count.hits;
        uint32_t src_bytes = query_count.bytes;

        memset(&query_count, 0, sizeof(struct rte_flow_query_count));
        query_count.reset = 1;

        if (flow_handler_info->dst_action_handle != NULL) {
            retval = rte_flow_async_action_handle_query(port_id, 0,
                    &flow_handler_info->rte_flow_bypass_data->op_attr,
                    flow_handler_info->dst_action_handle,
                    (void *)&query_count, NULL, &flow_error);
            rte_flow_push(port_id, 0, &flow_error);
            rte_flow_pull(port_id, 0, NULL, 0, &flow_error);
            if (retval != 0) {
                SCLogError("rte_flow dynamic bypass: action handle query error %s errmsg: %s",
                        rte_strerror(-retval), flow_error.message);
                SC_ATOMIC_ADD(flow_handler_info->livedev->dpdk_vars->rte_flow_bypass_data
                                      ->rte_bypass_query_error,
                        1);
            }
        }

        uint32_t dst_packets = query_count.hits;
        uint32_t dst_bytes = query_count.bytes;

        if (src_packets || dst_packets) {
            fc->tosrcpktcnt += src_packets;
            fc->tosrcbytecnt += src_bytes;
            fc->todstpktcnt += dst_packets;
            fc->todstbytecnt += dst_bytes;
            SCReturnInt(1);
        }
        SCReturnInt(0);
    }
#endif

    query_count.reset = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
    action[0].conf = &counter_id;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    retval = rte_flow_query(
            port_id, src_rule_handler, &(action[0]), (void *)&query_count, &flow_error);
    if (retval != 0) {
        SCLogError("rte_flow dynamic bypass: count query error %s errmsg: %s",
                rte_strerror(-retval), flow_error.message);
        SC_ATOMIC_ADD(flow_handler_info->rte_flow_bypass_data->rte_bypass_query_error, 1);
    };

    uint64_t src_packets = query_count.hits;
    uint64_t src_bytes = query_count.bytes;

    memset(&query_count, 0, sizeof(struct rte_flow_query_count));
    query_count.reset = 1;
    retval = rte_flow_query(
            port_id, dst_rule_handler, &(action[0]), (void *)&query_count, &flow_error);
    if (retval != 0) {
        SCLogError("rte_flow dynamic bypass: count query error %s errmsg: %s",
                rte_strerror(-retval), flow_error.message);
        SC_ATOMIC_ADD(
                flow_handler_info->livedev->dpdk_vars->rte_flow_bypass_data->rte_bypass_query_error,
                1);
    };

    uint64_t dst_packets = query_count.hits;
    uint64_t dst_bytes = query_count.bytes;

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

/**
 * \brief Create rte_flow drop rule for dynamic bypass
 *
 * Uses Template API (rte_flow_async_create + rte_flow_push) when available,
 * falling back to classic rte_flow_create otherwise.
 *
 * The Template API path mirrors src/conntrack-example.c: a per-flow indirect
 * COUNT action handle is created with rte_flow_async_action_handle_create,
 * then an INDIRECT action referencing it is passed to rte_flow_async_create.
 * This avoids the synchronous rte_flow_action_handle_create() call which is
 * unavailable (and segfaults) once rte_flow_configure() has switched the port
 * to the async Template API.
 *
 * \param rte_flow_bypass_data bypass data with template handles
 * \param items array of pattern items
 * \param port_id identificator of a port
 * \param flow_handler rte_flow rule handler
 * \param action_handle per-flow indirect COUNT action handle (Template API)
 * \return int 0 on success, negative value on error
 */
static int RteFlowBypassRuleCreate(RteFlowBypassData *rte_flow_bypass_data,
        struct rte_flow_item *items, int port_id, struct rte_flow **flow_handler,
        struct rte_flow_action_handle **action_handle)
{
    struct rte_flow_error flow_error = { 0 };
    int retval = 0;
    *action_handle = NULL;
    if (rte_flow_bypass_data->template_api_available) {
        /* Template API path (matches conntrack-example.c):
         * 1. Create per-flow indirect COUNT action handle asynchronously. */
        struct rte_flow_action_count count_conf = { 0 };
        struct rte_flow_action count_action = {
            .type = RTE_FLOW_ACTION_TYPE_COUNT,
            .conf = &count_conf,
        };
        struct rte_flow_indir_action_conf indir_conf = {
            .ingress = 1,
            .transfer = 0,
        };

        *action_handle = rte_flow_async_action_handle_create(port_id, 0,
                &rte_flow_bypass_data->op_attr, &indir_conf, &count_action, NULL, &flow_error);
        if (*action_handle == NULL) {
            SCLogError("rte_flow dynamic bypass: async COUNT handle create error: %s",
                    flow_error.message);
            retval = -1;
            goto rule_failed;
        }

        /* 2. Build actions referencing the per-flow indirect COUNT handle + DROP */
        struct rte_flow_action actions[] = {
            [0] = { .type = RTE_FLOW_ACTION_TYPE_INDIRECT, .conf = *action_handle },
            [1] = { .type = RTE_FLOW_ACTION_TYPE_DROP },
            [2] = { .type = RTE_FLOW_ACTION_TYPE_END },
        };

        *flow_handler = rte_flow_async_create(port_id, 0, /* queue_id = 0 */
                &rte_flow_bypass_data->op_attr, rte_flow_bypass_data->bypass_tbl,
                items, 0, /* pattern_template_index */
                actions,  /* per-flow actions */
                0,        /* actions_template_index */
                NULL,     /* user_data */
                &flow_error);

        if (*flow_handler == NULL) {
            SCLogError("rte_flow dynamic bypass: async create error: %s", flow_error.message);
            /* Destroy the handle we just created since the rule failed */
            rte_flow_async_action_handle_destroy(port_id, 0,
                    &rte_flow_bypass_data->op_attr, *action_handle, NULL, &flow_error);
            *action_handle = NULL;
            retval = -1;
            goto rule_failed;
        }

        /* Push to hardware immediately */
        retval = rte_flow_push(port_id, 0, &flow_error);
        if (retval < 0) {
            SCLogError("rte_flow dynamic bypass: push error: %s", flow_error.message);
            rte_flow_async_destroy(port_id, 0, &rte_flow_bypass_data->op_attr,
                    *flow_handler, NULL, &flow_error);
            rte_flow_async_action_handle_destroy(port_id, 0,
                    &rte_flow_bypass_data->op_attr, *action_handle, NULL, &flow_error);
            *flow_handler = NULL;
            *action_handle = NULL;
            goto rule_failed;
        }

        /* Pull completions to free any completed async ops */
        rte_flow_pull(port_id, 0, NULL, 0, &flow_error);

        SCReturnInt(0);
    } else {
        struct rte_flow_attr attr = { 0 };
        struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };

        attr.ingress = 1;
        attr.priority = 0;
        attr.group = RTE_JUMP_GROUP;

        uint32_t counter_id = COUNT_ACTION_ID;

        action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
        action[0].conf = &counter_id;
        action[1].type = RTE_FLOW_ACTION_TYPE_DROP;
        action[2].type = RTE_FLOW_ACTION_TYPE_END;

        retval = rte_flow_validate(port_id, &attr, items, action, &flow_error);
        if (retval != 0) {
            goto rule_failed;
        }

        *flow_handler = rte_flow_create(port_id, &attr, items, action, &flow_error);
        if (*flow_handler == NULL) {
            retval = -1;
            goto rule_failed;
        }
        SCReturnInt(retval);
    }

rule_failed:
    SCLogError("rte_flow dynamic bypass: create rte_flow rule error %s errmsg: %s",
            rte_strerror(-retval), flow_error.message);
    SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_rules_error, 1);
    SCReturnInt(-1);
}

/**
 * \brief Asynchronously destroy a per-flow indirect COUNT action handle.
 *
 * Matches the async lifecycle used in conntrack-example.c. No-op when the
 * classic API is in use (action handles do not exist there).
 */
static void RteFlowActionHandleDestroyFlow(RteFlowBypassData *rte_flow_bypass_data,
        uint16_t port_id, struct rte_flow_action_handle *action_handle)
{
    if (action_handle == NULL) {
        return;
    }
    struct rte_flow_error flow_error = { 0 };
    if (rte_flow_bypass_data != NULL && rte_flow_bypass_data->template_api_available) {
        int retval = rte_flow_async_action_handle_destroy(port_id, 0,
                &rte_flow_bypass_data->op_attr, action_handle, NULL, &flow_error);
        if (retval != 0) {
            SCLogError("rte_flow dynamic bypass: async action handle destroy error %s errmsg: %s",
                    rte_strerror(-retval), flow_error.message);
        }
        rte_flow_push(port_id, 0, &flow_error);
        rte_flow_pull(port_id, 0, NULL, 0, &flow_error);
    } else {
        rte_flow_action_handle_destroy(port_id, action_handle, &flow_error);
    }
}

static void RteFlowHandleEmergency(ThreadVars *tv, Flow *f, void *data)
{
    if (f->flow_state != FLOW_STATE_CAPTURE_BYPASSED &&
            (f->flow_end_flags & FLOW_END_FLAG_EMERGENCY) == 0) {
        return;
    }
    FlowBypassInfo *fc = SCFlowGetStorageById(f, GetFlowBypassInfoID());
    if (fc == NULL)
        return;
    RteFlowHandlerToFlow *flow_handler_info = (RteFlowHandlerToFlow *)fc->bypass_data;
    if (flow_handler_info == NULL)
        return;
    if (flow_handler_info->src_handler != NULL && flow_handler_info->dst_handler != NULL) {
        RteFlowBiRuleDestroy(flow_handler_info->rte_flow_bypass_data, flow_handler_info->livedev->dpdk_vars->port_id,
                flow_handler_info->src_handler, flow_handler_info->dst_handler);
        flow_handler_info->src_handler = NULL;
        flow_handler_info->dst_handler = NULL;
        SC_ATOMIC_SUB(flow_handler_info->rte_flow_bypass_data->rte_bypass_rules_active, 2);
    }
}

/**
 * \brief Destroy rte_flow rules for both directions of a flow
 *
 * \param port_id identificator of a port
 * \param src_handler handler of rte_flow rule
 * \param dst_handler handler of rte_flow rule
 */
static void RteFlowBiRuleDestroy(RteFlowBypassData *rte_flow_bypass_data,
        uint16_t port_id, struct rte_flow *src_handler, struct rte_flow *dst_handler)
{
    int retval = 0;
    struct rte_flow_error flow_error = { 0 };

    if (rte_flow_bypass_data != NULL && rte_flow_bypass_data->template_api_available) {
        if (src_handler != NULL) {
            retval = rte_flow_async_destroy(port_id, 0, &rte_flow_bypass_data->op_attr,
                    src_handler, NULL, &flow_error);
            if (retval != 0) {
                SCLogError("rte_flow dynamic bypass: async destroy error %s errmsg: %s",
                        rte_strerror(-retval), flow_error.message);
            }
        }
        if (dst_handler != NULL) {
            retval = rte_flow_async_destroy(port_id, 0, &rte_flow_bypass_data->op_attr,
                    dst_handler, NULL, &flow_error);
            if (retval != 0) {
                SCLogError("rte_flow dynamic bypass: async destroy error %s errmsg: %s",
                        rte_strerror(-retval), flow_error.message);
            }
        }
        rte_flow_push(port_id, 0, &flow_error);
        rte_flow_pull(port_id, 0, NULL, 0, &flow_error);
        return;
    }

    /* Fallback: classic API */
    if (src_handler != NULL) {
        retval = rte_flow_destroy(port_id, src_handler, &flow_error);
        if (retval != 0) {
            SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                    rte_strerror(-retval), flow_error.message);
        }
    }

    if (dst_handler != NULL) {
        retval = rte_flow_destroy(port_id, dst_handler, &flow_error);
        if (retval != 0) {
            SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                    rte_strerror(-retval), flow_error.message);
        }
    }
}

/**
 * \brief Poll flow data from rte_flow_ring structure and create rte_flow bypass rule to bypass flow
 *        from both directions
 *
 * \param th_v thread vars
 * \param bypassstats bypass stats
 * \param curtime time
 * \param data table of flows and rte_flow rule handlers
 * \return int number of successfully created rte_flow rules
 */
int RteFlowBypassRuleLoad(
        ThreadVars *th_v, struct flows_stats *bypassstats, struct timespec *curtime, void *data)
{
    SCEnter();
    RteFlowBypassData *rte_flow_bypass_data = (RteFlowBypassData *)data;
    struct rte_ring *bypass_ring = rte_flow_bypass_data->bypass_ring;
    struct rte_mempool *bypass_mp = rte_flow_bypass_data->bypass_mp;
    struct rte_flow_item items[] = { { 0 }, { 0 }, { 0 }, { 0 }, { 0 } };
    uint16_t L2_INDEX = 0, L3_INDEX = 1, L4_INDEX = 2, END_INDEX = 3;
    uint16_t ring_dequeue_num = 20;
    uint32_t success_count = 0;
    FlowKey *ring_data[ring_dequeue_num];

    memset(ring_data, 0, sizeof(ring_data));
    /* Initialize the reusable part of rte_flow rules */
    items[L2_INDEX].type = RTE_FLOW_ITEM_TYPE_ETH;
    items[END_INDEX].type = RTE_FLOW_ITEM_TYPE_END;

    uint32_t to_bypass_packets =
            rte_ring_dequeue_burst(bypass_ring, (void **)ring_data, ring_dequeue_num, NULL);
    for (uint16_t i = 0; i < to_bypass_packets; i++) {
        if (unlikely(suricata_ctl_flags != 0)) {
            SCReturnInt(success_count);
        }
        struct rte_flow_item_ipv4 ipv4_spec = { 0 }, ipv4_mask = { 0 };
        struct rte_flow_item_ipv6 ipv6_spec = { 0 }, ipv6_mask = { 0 };
        struct rte_flow_item_tcp tcp_spec = { 0 }, tcp_mask = { 0 };
        struct rte_flow_item_udp udp_spec = { 0 }, udp_mask = { 0 };
        void *ip_spec = NULL, *ip_mask = NULL, *l4_spec = NULL, *l4_mask = NULL;

        FlowKey *flow_key = ring_data[i];
        uint16_t port_id = flow_key->livedev->dpdk_vars->port_id;
        uint32_t flow_hash = FlowKeyGetHash(flow_key);
        Flow *flow = FlowGetExistingFlowFromHash(flow_key, flow_hash);
        rte_mempool_put(bypass_mp, flow_key);

        /* If error, destroy the rule for flow in original direction and set flow state to local
         * bypass*/
        if (flow == NULL || SC_ATOMIC_GET(rte_flow_bypass_data->rte_bypass_rules_active) + 2 >=
                                    rte_flow_bypass_data->rte_bypass_rule_capacity) {
            if (flow == NULL) {
                SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_flow_error, 1);
            } else {
                FlowUpdateState(flow, FLOW_STATE_LOCAL_BYPASSED);
                FLOWLOCK_UNLOCK(flow);
            }
            continue;
        }

        /* Create rte_flow rule for original direction */
        if (flow_key->src.family == AF_INET) {
            SCLogDebug("Add an IPv4 rte_flow bypass rule");
            ipv4_spec.hdr.src_addr = flow_key->src.address.address_un_data32[0];
            ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
            ipv4_spec.hdr.dst_addr = flow_key->dst.address.address_un_data32[0];
            ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
            ip_spec = &ipv4_spec;
            ip_mask = &ipv4_mask;
            items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV4;
        } else {
#if RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0)
            SCLogDebug("Add an IPv6 rte_flow bypass rule");
            memcpy(ipv6_spec.hdr.src_addr.a, flow_key->src.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.src_addr.a, 0xFF, 16);
            memcpy(ipv6_spec.hdr.dst_addr.a, flow_key->dst.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.dst_addr.a, 0xFF, 16);
#else
            SCLogDebug("Add an IPv6 rte_flow bypass rule");
            memcpy(ipv6_spec.hdr.src_addr, flow_key->src.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.src_addr, 0xFF, 16);
            memcpy(ipv6_spec.hdr.dst_addr, flow_key->dst.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.dst_addr, 0xFF, 16);
#endif /* RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0) */
            ip_spec = &ipv6_spec;
            ip_mask = &ipv6_mask;
            items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV6;
        }

        if (flow_key->proto == IPPROTO_TCP) {
            tcp_spec.hdr.src_port = htons(flow_key->sp);
            tcp_mask.hdr.src_port = 0xFFFF;
            tcp_spec.hdr.dst_port = htons(flow_key->dp);
            tcp_mask.hdr.dst_port = 0xFFFF;
            l4_spec = &tcp_spec;
            l4_mask = &tcp_mask;
            items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_TCP;
        } else {
            udp_spec.hdr.src_port = htons(flow_key->sp);
            udp_mask.hdr.src_port = 0xFFFF;
            udp_spec.hdr.dst_port = htons(flow_key->dp);
            udp_mask.hdr.dst_port = 0xFFFF;
            l4_spec = &udp_spec;
            l4_mask = &udp_mask;
            items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_UDP;
        }

        items[L3_INDEX].spec = ip_spec;
        items[L3_INDEX].mask = ip_mask;
        items[L4_INDEX].spec = l4_spec;
        items[L4_INDEX].mask = l4_mask;

        struct rte_flow *src_rule_handler = NULL;
        struct rte_flow_action_handle *src_action_handle = NULL;
        int retval = RteFlowBypassRuleCreate(rte_flow_bypass_data, items, port_id,
                &src_rule_handler, &src_action_handle);

        /* Create rte_flow rule for the opposite direction */
        if (flow_key->src.family == AF_INET) {
            SCLogDebug("Add an IPv4 rte_flow bypass rule in other direction");
            ipv4_spec.hdr.src_addr = flow_key->dst.address.address_un_data32[0];
            ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
            ipv4_spec.hdr.dst_addr = flow_key->src.address.address_un_data32[0];
            ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
            ip_spec = &ipv4_spec;
            ip_mask = &ipv4_mask;
            items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV4;
        } else {
            SCLogDebug("Add an IPv6 rte_flow bypass rule");
#if RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0)
            memcpy(ipv6_spec.hdr.src_addr.a, flow_key->dst.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.src_addr.a, 0xFF, 16);
            memcpy(ipv6_spec.hdr.dst_addr.a, flow_key->src.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.dst_addr.a, 0xFF, 16);
#else
            memcpy(ipv6_spec.hdr.src_addr, flow_key->src.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.src_addr, 0xFF, 16);
            memcpy(ipv6_spec.hdr.dst_addr, flow_key->dst.address.address_un_data8, 16);
            memset(ipv6_mask.hdr.dst_addr, 0xFF, 16);
#endif /* RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0) */
            ip_spec = &ipv6_spec;
            ip_mask = &ipv6_mask;
            items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV6;
        }

        if (flow_key->proto == IPPROTO_TCP) {
            tcp_spec.hdr.src_port = htons(flow_key->dp);
            tcp_mask.hdr.src_port = 0xFFFF;
            tcp_spec.hdr.dst_port = htons(flow_key->sp);
            tcp_mask.hdr.dst_port = 0xFFFF;
            l4_spec = &tcp_spec;
            l4_mask = &tcp_mask;
            items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_TCP;
        } else {
            udp_spec.hdr.src_port = htons(flow_key->dp);
            udp_mask.hdr.src_port = 0xFFFF;
            udp_spec.hdr.dst_port = htons(flow_key->sp);
            udp_mask.hdr.dst_port = 0xFFFF;
            l4_spec = &udp_spec;
            l4_mask = &udp_mask;
            items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_UDP;
        }

        items[L3_INDEX].spec = ip_spec;
        items[L3_INDEX].mask = ip_mask;
        items[L4_INDEX].spec = l4_spec;
        items[L4_INDEX].mask = l4_mask;

        struct rte_flow *dst_rule_handler = NULL;
        struct rte_flow_action_handle *dst_action_handle = NULL;
        retval += RteFlowBypassRuleCreate(rte_flow_bypass_data, items, port_id,
                &dst_rule_handler, &dst_action_handle);

        /* If error, destroy the rule for flow in original direction and set flow state to local
         * bypass*/
        if (retval != 0) {
            RteFlowBiRuleDestroy(rte_flow_bypass_data, port_id, src_rule_handler, dst_rule_handler);
            RteFlowActionHandleDestroyFlow(rte_flow_bypass_data, port_id, src_action_handle);
            RteFlowActionHandleDestroyFlow(rte_flow_bypass_data, port_id, dst_action_handle);
            FlowUpdateState(flow, FLOW_STATE_LOCAL_BYPASSED);
            FLOWLOCK_UNLOCK(flow);
            continue;
        }

        int inet_family = FLOW_IS_IPV4(flow) ? AF_INET : AF_INET6;

        retval = RteFlowSetFlowBypassInfo(flow, src_rule_handler, dst_rule_handler,
                src_action_handle, dst_action_handle, inet_family);
        if (retval == 0) {
            success_count++;
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_rules_active, 2);
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_rules_created, 2);
        }
        FLOWLOCK_UNLOCK(flow);
    }
    SCReturnInt(success_count);
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
    if (flow_handler_info->src_handler == NULL || flow_handler_info->dst_handler == NULL) {
        /* Rules already deleted */
        return false;
    }
    LiveDevice *livedev = LiveDeviceGetById(flow->livedev_id);
    bool activity = RteFlowUpdateStats(fc, livedev->dpdk_vars->port_id,
            flow_handler_info->src_handler, flow_handler_info->dst_handler);
    if (activity)
        flow->lastts = SCTIME_FROM_SECS(tsec);
    if (!activity || unlikely(suricata_ctl_flags != 0)) {
        if (flow_handler_info->src_handler != NULL && flow_handler_info->dst_handler != NULL) {
            uint16_t port_id = flow_handler_info->livedev->dpdk_vars->port_id;
            RteFlowBiRuleDestroy(flow_handler_info->rte_flow_bypass_data, port_id,
                    flow_handler_info->src_handler, flow_handler_info->dst_handler);
            /* Destroy per-flow indirect COUNT action handles (async-safe) */
            RteFlowActionHandleDestroyFlow(flow_handler_info->rte_flow_bypass_data, port_id,
                    flow_handler_info->src_action_handle);
            RteFlowActionHandleDestroyFlow(flow_handler_info->rte_flow_bypass_data, port_id,
                    flow_handler_info->dst_action_handle);
            flow_handler_info->src_action_handle = NULL;
            flow_handler_info->dst_action_handle = NULL;
            flow_handler_info->src_handler = NULL;
            flow_handler_info->dst_handler = NULL;
            SC_ATOMIC_SUB(flow_handler_info->rte_flow_bypass_data->rte_bypass_rules_active, 2);
        }
    }
    SCReturnBool(activity);
}

void RteBypassFree(void *data)
{
    RteFlowHandlerToFlow *flow_handler_info = (RteFlowHandlerToFlow *)data;
    if (flow_handler_info->src_handler != NULL && flow_handler_info->dst_handler != NULL) {
        FlowBypassInfo *fc = SCFlowGetStorageById(flow_handler_info->flow, GetFlowBypassInfoID());
        if (fc == NULL) {
            SCLogError("rte_flow dynamic bypass: flow_bypass_info is NULL");
            return;
        }
        LiveDevice *livedev = LiveDeviceGetById(flow_handler_info->flow->livedev_id);
        uint16_t port_id = livedev->dpdk_vars->port_id;
        RteFlowUpdateStats(fc, port_id,
                flow_handler_info->src_handler, flow_handler_info->dst_handler);
        RteFlowBiRuleDestroy(flow_handler_info->rte_flow_bypass_data, port_id,
                flow_handler_info->src_handler, flow_handler_info->dst_handler);
        /* Destroy per-flow indirect COUNT action handles (async-safe) */
        RteFlowActionHandleDestroyFlow(flow_handler_info->rte_flow_bypass_data, port_id,
                flow_handler_info->src_action_handle);
        RteFlowActionHandleDestroyFlow(flow_handler_info->rte_flow_bypass_data, port_id,
                flow_handler_info->dst_action_handle);
        flow_handler_info->src_action_handle = NULL;
        flow_handler_info->dst_action_handle = NULL;
        flow_handler_info->src_handler = NULL;
        flow_handler_info->dst_handler = NULL;
        SC_ATOMIC_SUB(flow_handler_info->rte_flow_bypass_data->rte_bypass_rules_active, 1);
    }
    if (flow_handler_info != NULL) {
        rte_mempool_put(flow_handler_info->livedev->dpdk_vars->rte_flow_bypass_data->bypass_info_mp,
                flow_handler_info);
    }
}

static int RteFlowSetFlowBypassInfo(Flow *flow, struct rte_flow *src_handler,
        struct rte_flow *dst_handler, struct rte_flow_action_handle *src_action_handle,
        struct rte_flow_action_handle *dst_action_handle, int family)
{
    FlowBypassInfo *fc = SCFlowGetStorageById(flow, GetFlowBypassInfoID());
    LiveDevice *livedev = LiveDeviceGetById(flow->livedev_id);
    if (fc) {
        if (fc->bypass_data != NULL) {
            SCReturnInt(0);
        }
        RteFlowHandlerToFlow *flow_handler_info;
        if (rte_mempool_get(livedev->dpdk_vars->rte_flow_bypass_data->bypass_info_mp,
                    (void **)&flow_handler_info) < 0) {
            SC_ATOMIC_ADD(livedev->dpdk_vars->rte_flow_bypass_data
                                  ->rte_bypass_info_mempool_get_error,
                    1);
            /* Mempool capacity has been reachead, switch to local bypass */
            goto bypass_fail;
        }
        flow_handler_info->flow = flow;
        flow_handler_info->src_handler = src_handler;
        flow_handler_info->dst_handler = dst_handler;
        flow_handler_info->src_action_handle = src_action_handle;
        flow_handler_info->dst_action_handle = dst_action_handle;
        flow_handler_info->livedev = livedev;
        flow_handler_info->rte_flow_bypass_data = livedev->dpdk_vars->rte_flow_bypass_data;
        fc->bypass_data = flow_handler_info;
        fc->BypassUpdate = RteBypassUpdate;
        fc->BypassFree = RteBypassFree;
        LiveDevAddBypassStats(livedev, 1, family);
        LiveDevAddBypassSuccess(livedev, 1, family);
        SCReturnInt(1);
    }

bypass_fail:;
    RteFlowBiRuleDestroy(livedev->dpdk_vars->rte_flow_bypass_data, livedev->dpdk_vars->port_id, src_handler, dst_handler);
    LiveDevAddBypassFail(livedev, 1, family);
    FlowUpdateState(flow, FLOW_STATE_LOCAL_BYPASSED);
    SCReturnInt(-ENOMEM);
}

int RteFlowBypassCallback(Packet *p)
{
    if (p == NULL || p->flow == NULL) {
        SCReturnInt(0);
    }

    /* Only bypass TCP and UDP */
    if (!(PacketIsTCP(p) || PacketIsUDP(p))) {
        SCReturnInt(0);
    }
    LiveDevice *livedev = LiveDeviceGetById(p->livedev_id);
    RteFlowBypassData *rte_flow_bypass_data = livedev->dpdk_vars->rte_flow_bypass_data;

    /* The tested rte_flow rule capacity of the device has been exhausted, new rules will be added
     * after bypassed flows will timeout and the existing rules are be deleted */
    if (SC_ATOMIC_GET(rte_flow_bypass_data->rte_bypass_rules_active) + 2 >=
            rte_flow_bypass_data->rte_bypass_rule_capacity) {
        SCReturnInt(0);
    }
    int retval = 0;
    if (rte_flow_bypass_data->template_api_available) {
        /* Template API direct path: build items and create async rules immediately */
        struct rte_flow_item items[] = {
            [0] = { .type = RTE_FLOW_ITEM_TYPE_ETH },
            [1] = { 0 },  /* IPv4 or IPv6 */
            [2] = { 0 },  /* TCP or UDP */
            [3] = { .type = RTE_FLOW_ITEM_TYPE_END },
        };

        struct rte_flow_item_ipv4 ipv4_spec = { 0 }, ipv4_mask = { 0 };
        struct rte_flow_item_ipv6 ipv6_spec = { 0 }, ipv6_mask = { 0 };
        struct rte_flow_item_tcp tcp_spec = { 0 }, tcp_mask = { 0 };
        struct rte_flow_item_udp udp_spec = { 0 }, udp_mask = { 0 };
        void *ip_spec = NULL, *ip_mask = NULL, *l4_spec = NULL, *l4_mask = NULL;

        uint16_t port_id = rte_flow_bypass_data->port_id;

        /* Build items for original direction */
        if (PacketIsIPv4(p)) {
            ipv4_spec.hdr.src_addr = GET_IPV4_SRC_ADDR_U32(p);
            ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
            ipv4_spec.hdr.dst_addr = GET_IPV4_DST_ADDR_U32(p);
            ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
            ip_spec = &ipv4_spec;
            ip_mask = &ipv4_mask;
            items[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
        } else if (PacketIsIPv6(p)) {
            memcpy(ipv6_spec.hdr.src_addr, GET_IPV6_SRC_ADDR(p), 16);
            memset(ipv6_mask.hdr.src_addr, 0xFF, 16);
            memcpy(ipv6_spec.hdr.dst_addr, GET_IPV6_DST_ADDR(p), 16);
            memset(ipv6_mask.hdr.dst_addr, 0xFF, 16);
            ip_spec = &ipv6_spec;
            ip_mask = &ipv6_mask;
            items[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
        }

        if (p->proto == IPPROTO_TCP) {
            tcp_spec.hdr.src_port = htons(p->sp);
            tcp_mask.hdr.src_port = 0xFFFF;
            tcp_spec.hdr.dst_port = htons(p->dp);
            tcp_mask.hdr.dst_port = 0xFFFF;
            l4_spec = &tcp_spec;
            l4_mask = &tcp_mask;
            items[2].type = RTE_FLOW_ITEM_TYPE_TCP;
        } else {
            udp_spec.hdr.src_port = htons(p->sp);
            udp_mask.hdr.src_port = 0xFFFF;
            udp_spec.hdr.dst_port = htons(p->dp);
            udp_mask.hdr.dst_port = 0xFFFF;
            l4_spec = &udp_spec;
            l4_mask = &udp_mask;
            items[2].type = RTE_FLOW_ITEM_TYPE_UDP;
        }

        items[1].spec = ip_spec;
        items[1].mask = ip_mask;
        items[2].spec = l4_spec;
        items[2].mask = l4_mask;

        /* Create per-flow indirect COUNT action handles asynchronously.
         * After rte_flow_configure() switches the port to the Template API,
         * the synchronous rte_flow_action_handle_create() is unavailable and
         * segfaults — so we must use the async variant (matching
         * conntrack-example.c). */
        struct rte_flow_error flow_error = { 0 };
        struct rte_flow_action_count count_conf = { 0 };
        struct rte_flow_action count_action = {
            .type = RTE_FLOW_ACTION_TYPE_COUNT,
            .conf = &count_conf,
        };
        struct rte_flow_indir_action_conf indir_conf = {
            .ingress = 1,
            .transfer = 0,
        };

        struct rte_flow_action_handle *src_action_handle =
                rte_flow_async_action_handle_create(
                        port_id, 0, &rte_flow_bypass_data->op_attr,
                        &indir_conf, &count_action, NULL, &flow_error);
        struct rte_flow_action_handle *dst_action_handle = NULL;
        if (src_action_handle != NULL) {
            dst_action_handle = rte_flow_async_action_handle_create(
                    port_id, 0, &rte_flow_bypass_data->op_attr,
                    &indir_conf, &count_action, NULL, &flow_error);
        }
        if (src_action_handle == NULL || dst_action_handle == NULL) {
            SCLogError("rte_flow dynamic bypass: async COUNT handle create error: %s",
                    flow_error.message);
            RteFlowActionHandleDestroyFlow(rte_flow_bypass_data, port_id, src_action_handle);
            RteFlowActionHandleDestroyFlow(rte_flow_bypass_data, port_id, dst_action_handle);
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_rules_error, 1);
            SCReturnInt(0);
        }

        /* Build per-flow actions with indirect COUNT handles */
        struct rte_flow_action src_actions[] = {
            [0] = { .type = RTE_FLOW_ACTION_TYPE_INDIRECT,
                    .conf = src_action_handle },
            [1] = { .type = RTE_FLOW_ACTION_TYPE_DROP },
            [2] = { .type = RTE_FLOW_ACTION_TYPE_END },
        };
        struct rte_flow_action dst_actions[] = {
            [0] = { .type = RTE_FLOW_ACTION_TYPE_INDIRECT,
                    .conf = dst_action_handle },
            [1] = { .type = RTE_FLOW_ACTION_TYPE_DROP },
            [2] = { .type = RTE_FLOW_ACTION_TYPE_END },
        };

        /* Create src-direction rule with per-flow actions */
        struct rte_flow *src_handler = rte_flow_async_create(
                port_id, 0, &rte_flow_bypass_data->op_attr,
                rte_flow_bypass_data->bypass_tbl,
                items, 0, src_actions, 0, NULL, &flow_error);
        if (src_handler == NULL) {
            SCLogError("rte_flow dynamic bypass: async create error: %s", flow_error.message);
            RteFlowActionHandleDestroyFlow(rte_flow_bypass_data, port_id, src_action_handle);
            RteFlowActionHandleDestroyFlow(rte_flow_bypass_data, port_id, dst_action_handle);
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_rules_error, 1);
            SCReturnInt(0);
        }

        /* Swap src/dst for reverse direction */
        if (PacketIsIPv4(p)) {
            ipv4_spec.hdr.src_addr = GET_IPV4_DST_ADDR_U32(p);
            ipv4_spec.hdr.dst_addr = GET_IPV4_SRC_ADDR_U32(p);
        } else {
            memcpy(ipv6_spec.hdr.src_addr, GET_IPV6_DST_ADDR(p), 16);
            memcpy(ipv6_spec.hdr.dst_addr, GET_IPV6_SRC_ADDR(p), 16);
        }

        if (p->proto == IPPROTO_TCP) {
            tcp_spec.hdr.src_port = htons(p->dp);
            tcp_spec.hdr.dst_port = htons(p->sp);
        } else {
            udp_spec.hdr.src_port = htons(p->dp);
            udp_spec.hdr.dst_port = htons(p->sp);
        }

        items[1].spec = ip_spec;
        items[1].mask = ip_mask;
        items[2].spec = l4_spec;
        items[2].mask = l4_mask;

        /* Create dst-direction rule with per-flow actions */
        struct rte_flow *dst_handler = rte_flow_async_create(
                port_id, 0, &rte_flow_bypass_data->op_attr,
                rte_flow_bypass_data->bypass_tbl,
                items, 0, dst_actions, 0, NULL, &flow_error);
        if (dst_handler == NULL) {
            SCLogError("rte_flow dynamic bypass: async create error: %s", flow_error.message);
            rte_flow_async_destroy(port_id, 0, &rte_flow_bypass_data->op_attr,
                    src_handler, NULL, &flow_error);
            RteFlowActionHandleDestroyFlow(rte_flow_bypass_data, port_id, src_action_handle);
            RteFlowActionHandleDestroyFlow(rte_flow_bypass_data, port_id, dst_action_handle);
            rte_flow_push(port_id, 0, &flow_error);
            rte_flow_pull(port_id, 0, NULL, 0, &flow_error);
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_rules_error, 1);
            SCReturnInt(0);
        }

        /* Push both rules to hardware */
        int ret = rte_flow_push(port_id, 0, &flow_error);
        if (ret < 0) {
            SCLogError("rte_flow dynamic bypass: push error: %s", flow_error.message);
            rte_flow_async_destroy(port_id, 0, &rte_flow_bypass_data->op_attr,
                    src_handler, NULL, &flow_error);
            rte_flow_async_destroy(port_id, 0, &rte_flow_bypass_data->op_attr,
                    dst_handler, NULL, &flow_error);
            RteFlowActionHandleDestroyFlow(rte_flow_bypass_data, port_id, src_action_handle);
            RteFlowActionHandleDestroyFlow(rte_flow_bypass_data, port_id, dst_action_handle);
            rte_flow_push(port_id, 0, &flow_error);
            rte_flow_pull(port_id, 0, NULL, 0, &flow_error);
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_rules_error, 1);
            SCReturnInt(0);
        }
        rte_flow_pull(port_id, 0, NULL, 0, &flow_error);

        int inet_family = PacketIsIPv4(p) ? AF_INET : AF_INET6;
        int retval = RteFlowSetFlowBypassInfo(
                p->flow, src_handler, dst_handler,
                src_action_handle, dst_action_handle, inet_family);
        if (retval != 0) {
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_rules_active, 1);
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_rules_created, 1);
        }
        SCReturnInt(retval);
    /* Fallback to regular API, DO NOT USE */
    } else {
        FlowKey *flow_key = NULL;

        if (rte_mempool_get(rte_flow_bypass_data->bypass_mp, (void **)&flow_key) < 0) {
            SCLogError("Memory allocation for rte_flow bypass data failed");
            SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_mempool_get_error, 1);
            SCReturnInt(0);
        }

        if (PacketIsIPv4(p)) {
            flow_key->src.family = AF_INET;
            flow_key->src.address.address_un_data32[0] = (GET_IPV4_SRC_ADDR_U32(p));
            flow_key->dst.family = AF_INET;
            flow_key->dst.address.address_un_data32[0] = (GET_IPV4_DST_ADDR_U32(p));
        } else if (PacketIsIPv6(p)) {
            flow_key->src.family = AF_INET6;
            memcpy(flow_key->src.address.address_un_data8, GET_IPV6_SRC_ADDR(p),
                    16 * sizeof(uint8_t));
            flow_key->dst.family = AF_INET6;
            memcpy(flow_key->dst.address.address_un_data8, GET_IPV6_DST_ADDR(p),
                    16 * sizeof(uint8_t));
        }
        if (p->proto == IPPROTO_TCP) {
            flow_key->proto = IPPROTO_TCP;
        } else {
            flow_key->proto = IPPROTO_UDP;
        }
        flow_key->sp = p->sp;
        flow_key->dp = p->dp;
        LiveDevice *livedev = LiveDeviceGetById(p->livedev_id);
        flow_key->livedev_id = livedev->id;
        flow_key->livedev = livedev;
        flow_key->vlan_id[0] = p->vlan_id[0];
        flow_key->vlan_id[1] = p->vlan_id[1];
        flow_key->vlan_id[2] = p->vlan_id[2];
        flow_key->recursion_level = 0;

        retval = rte_ring_mp_enqueue(rte_flow_bypass_data->bypass_ring, flow_key);

        /* If ring is full, continue with local bypass. Also, if Suricata shutdowns, do not increase
            * counters */
        if (retval < 0 || unlikely(suricata_ctl_flags != 0)) {
            rte_mempool_put(rte_flow_bypass_data->bypass_mp, flow_key);
            if (retval < 0)
                SC_ATOMIC_ADD(rte_flow_bypass_data->rte_bypass_enqueue_error, 1);
        }
        retval = retval == 0 ? 1 : 0;
    }
    SCReturnInt(retval);
}

/**
 * @}
 */

#endif /* HAVE_DPDK */
