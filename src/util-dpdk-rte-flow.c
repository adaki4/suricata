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
#include "runmode-dpdk.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-ice.h"
#include "util-dpdk-rte-flow.h"
#include "util-dpdk-rte-flow-pattern.h"

#ifdef HAVE_DPDK
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)

#define INITIAL_RTE_FLOW_RULE_COUNT_CAPACITY 5
#define DATA_BUFFER_SIZE                     1024
#define COUNT_ACTION_ID                      128

static int RteFlowRuleStorageInit(RteFlowRuleStorage *);
static int RteFlowRuleStorageAddRule(RteFlowRuleStorage *, const char *);
static int RteFlowRuleStorageExtendCapacity(RteFlowRuleStorage *);
static void DriverSpecificErrorMessage(const char *, struct rte_flow_item *);

/**
 * \brief Specify ambigous error messages as some drivers have specific
 *        behaviour when creating rte_flow rules
 *
 * \param driver_name name of a driver
 * \param items array of pattern items
 */
static void DriverSpecificErrorMessage(const char *driver_name, struct rte_flow_item *items)
{
    if (strcmp(driver_name, "net_ice") == 0) {
        iceDeviceRteFlowPatternError(items);
    }
}


static int RteFlowRuleStorageInit(RteFlowRuleStorage *rte_flow_rule_storage)
{
    SCEnter();
    rte_flow_rule_storage->curr_rte_flow_rule_count = 0;
    rte_flow_rule_storage->max_rte_flow_rule_count = INITIAL_RTE_FLOW_RULE_COUNT_CAPACITY;
    rte_flow_rule_storage->rte_flow_rules =
            SCMalloc(rte_flow_rule_storage->max_rte_flow_rule_count * sizeof(char *));

    if (rte_flow_rule_storage->rte_flow_rules == NULL) {
        SCLogError("Setup memory allocation for rte_flow rule storage failed");
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

static int RteFlowRuleStorageAddRule(
        RteFlowRuleStorage *rte_flow_rule_storage, const char *rte_flow_rule)
{
    SCEnter();
    size_t rule_len = (strlen(rte_flow_rule) + 1) * sizeof(char);
    rte_flow_rule_storage->rte_flow_rules[rte_flow_rule_storage->curr_rte_flow_rule_count] =
            SCMalloc(rule_len);
    if (rte_flow_rule_storage->rte_flow_rules[rte_flow_rule_storage->curr_rte_flow_rule_count] ==
            NULL) {
        SCLogError("Memory allocation for rte_flow rule string failed");
        RteFlowRuleStorageFree(rte_flow_rule_storage);
        SCReturnInt(-1);
    }

    strlcpy(rte_flow_rule_storage->rte_flow_rules[rte_flow_rule_storage->curr_rte_flow_rule_count],
            rte_flow_rule, rule_len);
    rte_flow_rule_storage->curr_rte_flow_rule_count++;

    if (rte_flow_rule_storage->curr_rte_flow_rule_count ==
            rte_flow_rule_storage->max_rte_flow_rule_count) {
        int retval = RteFlowRuleStorageExtendCapacity(rte_flow_rule_storage);
        if (retval != 0) {
            SCReturnInt(retval);
        }
    }
    SCReturnInt(0);
}

static int RteFlowRuleStorageExtendCapacity(RteFlowRuleStorage *rte_flow_rule_storage)
{
    SCEnter();
    char **tmp_rules;

    rte_flow_rule_storage->max_rte_flow_rule_count =
            2 * rte_flow_rule_storage->max_rte_flow_rule_count;

    tmp_rules = SCRealloc(rte_flow_rule_storage->rte_flow_rules,
            rte_flow_rule_storage->max_rte_flow_rule_count * sizeof(char *));
    if (tmp_rules == NULL) {
        SCLogError("Memory reallocation for rte_flow rule storage failed");
        RteFlowRuleStorageFree(rte_flow_rule_storage);
        SCReturnInt(-1);
    }

    rte_flow_rule_storage->rte_flow_rules = tmp_rules;
    SCReturnInt(0);
}
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0) */

/**
 * \brief Deallocation of memory containing user set rte_flow rules
 *
 * \param rte_flow_rule_storage rules loaded from suricata.yaml
 */
void RteFlowRuleStorageFree(RteFlowRuleStorage *rte_flow_rule_storage)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)

    if (rte_flow_rule_storage->rte_flow_rules == NULL) {
        SCReturn;
    }
    for (int i = 0; i < rte_flow_rule_storage->curr_rte_flow_rule_count; ++i) {
        SCFree(rte_flow_rule_storage->rte_flow_rules[i]);
    }
    SCFree(rte_flow_rule_storage->rte_flow_rules);
    rte_flow_rule_storage->rte_flow_rules = NULL;
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0) */
}

/**
 * \brief Load rte_flow rules patterns from suricata.yaml
 *
 * \param if_root root node in suricata.yaml
 * \param if_default default value
 * \param filter_type type of rte_flow rules to be loaded, only drop_filter is supported
 * \param rte_flow_rule_storage pointer to structure to load rte_flow rules into
 * \return int 0 on success, -1 on error
 */
int ConfigLoadRteFlowRules(ConfNode *if_root, ConfNode *if_default, const char *filter_type,
        RteFlowRuleStorage *rte_flow_rule_storage)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)
    SCEnter();
    ConfNode *node = ConfNodeLookupChild(if_root, filter_type);
    if (node == NULL) {
        SCLogInfo("No configurtion node found for %s", filter_type);
    } else {
        ConfNode *rule_node;
        const char *rte_flow_rule;
        int retval = RteFlowRuleStorageInit(rte_flow_rule_storage);
        if (retval != 0) {
            SCReturnInt(retval);
        }

        TAILQ_FOREACH (rule_node, &node->head, next) {
            if (strcmp(rule_node->val, "rule") == 0) {
                ConfGetChildValueWithDefault(rule_node, if_default, "rule", &rte_flow_rule);
                retval = RteFlowRuleStorageAddRule(rte_flow_rule_storage, rte_flow_rule);
                if (retval != 0) {
                    SCReturnInt(retval);
                }
            }
        }
    }
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0) */
    SCReturnInt(0);
}

/**
 * \brief Create rte_flow drop rules with patterns stored in rte_flow_rule_storage on a port with id
 *        port_id
 *
 * \param port_name name of a port
 * \param port_id identificator of a port
 * \param rte_flow_rule_storage pointer to structure containing rte_flow rule patterns
 * \param driver_name name of a driver
 * \return int 0 on success, -1 on error
 */
int CreateRteFlowRules(char *port_name, int port_id, RteFlowRuleStorage *rte_flow_rule_storage,
        const char *driver_name)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)
    SCEnter();
    int failed_rte_flow_rule_count = 0;
    struct rte_flow_error flush_error = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };

    attr.ingress = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    rte_flow_rule_storage->rte_flow_rule_handlers =
            SCMalloc(rte_flow_rule_storage->curr_rte_flow_rule_count * sizeof(struct rte_flow *));
    if (rte_flow_rule_storage->rte_flow_rule_handlers == NULL) {
        SCLogError("%s: Memory allocation for rte_flow rule string failed", port_name);
        RteFlowRuleStorageFree(rte_flow_rule_storage);
        SCReturnInt(-1);
    }

    for (int i = 0; i < rte_flow_rule_storage->curr_rte_flow_rule_count; i++) {
        struct rte_flow_item *items = { 0 };
        struct rte_flow_error flow_error = { 0 };
        uint8_t items_data_buffer[DATA_BUFFER_SIZE] = { 0 };

        int retval = ParsePattern(rte_flow_rule_storage->rte_flow_rules[i], items_data_buffer,
                sizeof(items_data_buffer), &items);
        if (retval != 0) {
            failed_rte_flow_rule_count++;
            SCLogError("%s: Error when parsing rte_flow rule: %s", port_name,
                    rte_flow_rule_storage->rte_flow_rules[i]);
            continue;
        }

        retval = rte_flow_validate(port_id, &attr, items, action, &flow_error);
        if (retval != 0) {
            failed_rte_flow_rule_count++;
            SCLogError("%s: rte_flow rule with pattern %s validation error: %s, errmsg: %s",
                    port_name, rte_flow_rule_storage->rte_flow_rules[i], rte_strerror(-retval),
                    flow_error.message);
            DriverSpecificErrorMessage(driver_name, items);
            continue;
        }

        struct rte_flow *flow_handler = rte_flow_create(port_id, &attr, items, action, &flow_error);
        if (flow_handler == NULL) {
            failed_rte_flow_rule_count++;
            SCLogError("%s: rte_flow rule with pattern %s creation error: %s", port_name,
                    rte_flow_rule_storage->rte_flow_rules[i], flow_error.message);
            continue;
        }
        rte_flow_rule_storage->rte_flow_rule_handlers[i] = flow_handler;
        SCLogInfo("%s: rte_flow rule with pattern: %s created", port_name,
                rte_flow_rule_storage->rte_flow_rules[i]);
    }

    if (failed_rte_flow_rule_count) {
        SCLogError("%s: Error parsing/creating %i rte_flow rule(s), flushing rules", port_name,
                failed_rte_flow_rule_count);
        int retval = rte_flow_flush(port_id, &flush_error);
        if (retval != 0) {
            SCLogError("%s Unable to flush rte_flow rules: %s Flush error msg: %s", port_name,
                    rte_strerror(-retval), flush_error.message);
        }
        SCReturnInt(-1);
    }
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)*/
    SCReturnInt(0);
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
