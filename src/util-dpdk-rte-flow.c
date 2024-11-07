/* Copyright (C) 2024 Open Information Security Foundation
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

#include "runmode-dpdk.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-rte-flow.h"
#include "util-dpdk-rte-flow-pattern.h"

#ifdef HAVE_DPDK

#define INITIAL_RULE_COUNT_CAPACITY 5
#define DATA_BUFFER_SIZE            1024

static int RuleStorageSetup(RuleStorage *);
static int RuleStorageAddRule(RuleStorage *, const char *);
static int RuleStorageExtendCapacity(RuleStorage *);

static int RuleStorageSetup(RuleStorage *rule_storage)
{
    SCEnter();
    rule_storage->curr_rule_count = 0;
    rule_storage->max_rule_count = INITIAL_RULE_COUNT_CAPACITY;
    rule_storage->rules = SCMalloc(rule_storage->max_rule_count * sizeof(char *));

    if (rule_storage->rules == NULL) {
        SCLogError("Setup memory allocation for rte_flow rule storage failed");
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

static int RuleStorageAddRule(RuleStorage *rule_storage, const char *rule)
{
    SCEnter();
    size_t rule_len = (strlen(rule) + 1) * sizeof(char);
    rule_storage->rules[rule_storage->curr_rule_count] = SCMalloc(rule_len);
    if (rule_storage->rules[rule_storage->curr_rule_count] == NULL) {
        SCLogError("Memory allocation for rte_flow rule string failed");
        RuleStorageFree(rule_storage);
        SCReturnInt(-1);
    }

    strlcpy(rule_storage->rules[rule_storage->curr_rule_count], rule, rule_len);
    rule_storage->curr_rule_count++;

    if (rule_storage->curr_rule_count == rule_storage->max_rule_count) {
        int retval = RuleStorageExtendCapacity(rule_storage);
        if (retval != 0) {
            SCReturnInt(retval);
        }
    }
    SCReturnInt(0);
}

static int RuleStorageExtendCapacity(RuleStorage *rule_storage)
{
    SCEnter();
    char **tmp_rules;

    rule_storage->max_rule_count = 2 * rule_storage->max_rule_count;

    tmp_rules = SCRealloc(rule_storage->rules, rule_storage->max_rule_count * sizeof(char *));
    if (tmp_rules == NULL) {
        SCLogError("Memory reallocation for rte_flow rule storage failed");
        RuleStorageFree(rule_storage);
        SCReturnInt(-1);
    }

    rule_storage->rules = tmp_rules;
    SCReturnInt(0);
}

void RuleStorageFree(RuleStorage *rule_storage)
{
    if (rule_storage->rules == NULL) {
        SCReturn;
    }
    for (int i = 0; i < rule_storage->curr_rule_count; ++i) {
        SCFree(rule_storage->rules[i]);
    }
    SCFree(rule_storage->rules);
    rule_storage->rules = NULL;
}

int ConfigLoadRTEFlowRules(
        ConfNode *if_root, ConfNode *if_default, const char *filter_type, RuleStorage *rule_storage)
{
    SCEnter();
    ConfNode *node = ConfNodeLookupChild(if_root, filter_type);
    if (node == NULL) {
        SCLogInfo("No configurtion node found for %s", filter_type);
    } else {
        ConfNode *rule_node;
        const char *rule;
        int retval = RuleStorageSetup(rule_storage);
        if (retval != 0) {
            SCReturnInt(retval);
        }

        TAILQ_FOREACH (rule_node, &node->head, next) {
            if (strcmp(rule_node->val, "rule") == 0) {
                ConfGetChildValueWithDefault(rule_node, if_default, "rule", &rule);
                retval = RuleStorageAddRule(rule_storage, rule);
                if (retval != 0) {
                    SCReturnInt(retval);
                }
            }
        }
    }
    SCReturnInt(0);
}

/**
 * \brief Check and log whether pattern is broad / not-specific
 *        as ice does not accept them                  */
static void iceDeviceError(struct rte_flow_item *items)
{
    int i = 0;
    while (items[i].type != RTE_FLOW_ITEM_TYPE_END) {
        if (items[i].spec != NULL) {
            SCReturn;
        }
        ++i;
    }
    SCLogError("ice driver does not support broad patterns");
}

/**
 * \brief Specify ambigous error messages as some drivers have specific
 * behaviour when creating rte_flow rules */
static void DriverSpecificErrorMessage(char *driver_name, struct rte_flow_item *items)
{
    if (strcmp(driver_name, "net_ice") == 0) {
        iceDeviceError(items);
    }
}

int CreateRules(char *port_name, int port_id, RuleStorage *rule_storage, char *driver_name)
{
    SCEnter();
    int failed_count = 0;
    struct rte_flow_error flush_error = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow *flow;

    attr.ingress = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    for (int i = 0; i < rule_storage->curr_rule_count; i++) {
        struct rte_flow_item *items = { 0 };
        struct rte_flow_error flow_error = { 0 };
        uint8_t data[DATA_BUFFER_SIZE] = { 0 };

        int ret;
        if ((ret = ParsePattern(rule_storage->rules[i], data, sizeof(data), &items)) != 0) {
            failed_count++;
            SCLogError("Error when parsing rte_flow rule: %s", rule_storage->rules[i]);
            continue;
        } else if ((ret = rte_flow_validate(port_id, &attr, items, action, &flow_error)) != 0) {
            failed_count++;
            SCLogError("Error when validating rte_flow rule with pattern %s for port %s: %s "
                       "errmsg: %s",
                    rule_storage->rules[i], port_name, rte_strerror(-ret), flow_error.message);
            DriverSpecificErrorMessage(driver_name, items);
            continue;
        } else if ((flow = rte_flow_create(port_id, &attr, items, action, &flow_error)) == NULL) {
            failed_count++;
            SCLogError("Error when creating rte_flow rule with pattern %s on %s: %s",
                    rule_storage->rules[i], port_name, flow_error.message);
        } else {
            SCLogInfo("rte_flow rule with pattern: %s created for port %s", rule_storage->rules[i],
                    port_name);
        }
    }
    RuleStorageFree(rule_storage);

    if (failed_count) {
        SCLogError("Error parsing/creating %i rte_flow rule(s), flushing rules on port %s",
                failed_count, port_name);
        int ret = rte_flow_flush(port_id, &flush_error);
        if (ret != 0) {
            SCLogError("Unable to flush rte_flow rules of %s: %s Flush error msg: %s", port_name,
                    rte_strerror(-ret), flush_error.message);
        }
        SCReturn(-1);
    }

    SCReturnInt(0);
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
