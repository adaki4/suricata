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

#include "decode.h"
#include "runmode-dpdk.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-rte-flow.h"
#include "util-dpdk-rte-flow-pattern.h"

#ifdef HAVE_DPDK
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)

#define INITIAL_RULE_COUNT_CAPACITY 5
#define DATA_BUFFER_SIZE            1024

static int RuleStorageSetup(RuleStorage *);
static int RuleStorageAddRule(RuleStorage *, const char *);
static int RuleStorageExtendCapacity(RuleStorage *);
static void iceDeviceError(struct rte_flow_item *);
static void DriverSpecificErrorMessage(const char *, struct rte_flow_item *);
static bool RTEFlowRuleHasPatternWildcard(struct rte_flow_item *);
static void InitRTEFlowDropFilter(struct rte_flow_item *, struct rte_flow_attr *, struct rte_flow_action *, const char *, const char *, uint32_t *);


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

/**
 * \brief Check and log whether pattern is broad / not-specific
 *        as ice does not accept them
 *
 * \param items array of pattern items
 */
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
 * behaviour when creating rte_flow rules
 *
 * \param driver_name name of a driver
 * \param items array of pattern items
 */
static void DriverSpecificErrorMessage(const char *driver_name, struct rte_flow_item *items)
{
    if (strcmp(driver_name, "net_ice") == 0) {
        iceDeviceError(items);
    }
}
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0) */


static void InitRTEFlowDropFilter(struct rte_flow_item *items, struct rte_flow_attr *attr, struct rte_flow_action *action, const char *driver_name, const char *port_name, uint32_t *counter_id) {
    if (strcmp(driver_name, "net_ice") == 0) {
        if (RTEFlowRuleHasPatternWildcard(items) == true) {
            action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
            action[1].type = RTE_FLOW_ACTION_TYPE_END;
            SCLogWarning("%s: gathering statistic for the rule is disabled because of wildcard pattern (ice PMD issue)", port_name);
            return;         
        }
#if RTE_VERSION >= RTE_VERSION_NUM(23, 11, 0, 0)
        attr->group = 2;
#else
        attr->group = 0;
#endif /* RTE_VERSION >= RTE_VERSION_NUM(23, 11, 0, 0) */
    }

    if (strcmp(driver_name, "net_ice") == 0 || strcmp(driver_name, "mlx5_core") == 0) {
        action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
        action[0].conf = counter_id;
        action[1].type = RTE_FLOW_ACTION_TYPE_DROP;
        action[2].type = RTE_FLOW_ACTION_TYPE_END;
    }
    else {
        action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
        action[1].type = RTE_FLOW_ACTION_TYPE_END;
    }
}

static bool RTEFlowRuleHasPatternWildcard(struct rte_flow_item *items) {
    int i = 0;
    while (items[i].type != RTE_FLOW_ITEM_TYPE_END) {
        if (items[i].mask != NULL || items[i].last != NULL) {
            struct rte_flow_item_ipv4 *ipv4 = (struct rte_flow_item_ipv4*) items[i].mask;
            SCLogWarning("type: %d, mask_src: %d mask_dst: %d", items[i].type, ipv4->hdr.src_addr, ipv4->hdr.dst_addr);
            return true;
        }
        i++;
    }
    return false;
}

/**
 * \brief Deallocation of memory containing user set rte_flow rules
 *
 * \param rule_storage rules loaded from suricata.yaml
 */
void RuleStorageFree(RuleStorage *rule_storage)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)
    if (rule_storage->rules == NULL) {
        SCReturn;
    }
    for (int i = 0; i < rule_storage->curr_rule_count; ++i) {
        SCFree(rule_storage->rules[i]);
    }
    SCFree(rule_storage->rules);
    rule_storage->rules = NULL;

#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0) */
}

/**
 * \brief Load rte_flow rules patterns from suricata.yaml
 *
 * \param if_root root node in suricata.yaml
 * \param if_default default value
 * \param filter_type type of rte_flow rules to be loaded, only drop_filter is supported
 * \param rule_storage pointer to structure to load rte_flow rules into
 * \return int 0 on success, -1 on failure
 */
int ConfigLoadRTEFlowRules(
        ConfNode *if_root, ConfNode *if_default, const char *filter_type, RuleStorage *rule_storage)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)
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
#endif
    SCReturnInt(0);
}

/**
 * \brief
 *
 * \param rte_flow_rules
 * \param rule_count
 * \param port_id
 * \param filtered_packets
 * \param flow_error
 * \return int
 */
int QueryRTEFlowFilteredPackets(struct rte_flow **rte_flow_rules, uint16_t rule_count, int port_id,
        uint64_t *filtered_packets, struct rte_flow_error *flow_error)
{
    struct rte_flow_query_count query_count = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };
    uint32_t counter_id = 128;

    query_count.reset = 0;
    action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
    action[0].conf = &counter_id;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    for (uint16_t i = 0; i < rule_count; i++) {
        int query_ret = rte_flow_query(
                port_id, rte_flow_rules[i], &(action[0]), (void *)&query_count, flow_error);
        if (query_ret != 0) {
            return query_ret;
        }
        *filtered_packets += query_count.hits;
    }

    return 0;
}

/**
 * \brief Create rte_flow drop rules with patterns stored in rule_storage on a port with id port_id
 *
 * \param port_name name of a port
 * \param port_id identificator of a port
 * \param rule_storage pointer to structure containing rte_flow rule patterns
 * \param driver_name name of a driver
 * \return int 0 on success, -1 on error
 */
int CreateRules(char *port_name, int port_id, RuleStorage *rule_storage, const char *driver_name)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)
    SCEnter();
    bool wildcard_present = false;
    int failed_count = 0;
    struct rte_flow_error flush_error = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };

    uint32_t counter_id = 128;

    attr.ingress = 1;
    // if (strcmp(driver_name, "net_ice") == 0 || strcmp(driver_name, "mlx5_pci") == 0) {
    //     action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
    //     action[0].conf = &counter_id;
    //     action[1].type = RTE_FLOW_ACTION_TYPE_DROP;
    //     action[2].type = RTE_FLOW_ACTION_TYPE_END;
    // } else {
    //     action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
    //     action[1].type = RTE_FLOW_ACTION_TYPE_END;
    // }

    rule_storage->rule_handlers =
            SCMalloc(sizeof(struct rte_flow_rule *) * rule_storage->curr_rule_count);
    if (rule_storage->rule_handlers == NULL) {
        SCLogError("Memory allocation for rte_flow rule string failed");
        RuleStorageFree(rule_storage);
        SCReturnInt(-1);
    }

    for (int i = 0; i < rule_storage->curr_rule_count; i++) {
        struct rte_flow_item *items = { 0 };
        struct rte_flow_error flow_error = { 0 };
        uint8_t data[DATA_BUFFER_SIZE] = { 0 };

        int ret = ParsePattern(rule_storage->rules[i], data, sizeof(data), &items);
        if (ret != 0) {
            failed_count++;
            SCLogError("Error when parsing rte_flow rule: %s", rule_storage->rules[i]);
            continue;
        }

        InitRTEFlowDropFilter(items, &attr, action, driver_name, port_name, &counter_id);        

        ret = rte_flow_validate(port_id, &attr, items, action, &flow_error);
        if (ret != 0) {
            failed_count++;
            SCLogError("Error when validating rte_flow rule with pattern %s for port %s: %s "
                       "errmsg: %s",
                    rule_storage->rules[i], port_name, rte_strerror(-ret), flow_error.message);
            DriverSpecificErrorMessage(driver_name, items);
            continue;
        }

        struct rte_flow *flow = rte_flow_create(port_id, &attr, items, action, &flow_error);
        if (flow == NULL) {
            failed_count++;
            SCLogError("Error when creating rte_flow rule with pattern %s on %s: %s",
                    rule_storage->rules[i], port_name, flow_error.message);
            continue;
        }
        rule_storage->rule_handlers[i] = flow;
        SCLogInfo("rte_flow rule with pattern: %s  for port %s", rule_storage->rules[i], port_name);
    }

    if (failed_count) {
        SCLogError("Error parsing/creating %i rte_flow rule(s), flushing rules on port %s",
                failed_count, port_name);
        int ret = rte_flow_flush(port_id, &flush_error);
        if (ret != 0) {
            SCLogError("Unable to flush rte_flow rules of %s: %s Flush error msg: %s", port_name,
                    rte_strerror(-ret), flush_error.message);
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
