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

#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-rte-flow.h"
#include "util-dpdk-rte-flow-pattern.h"
#include "runmode-dpdk.h"

#ifdef HAVE_DPDK
// static void* TokenizeRules(RuleStorage *rule_storage);

static void RuleStorageFree(RuleStorage *rule_storage) {
    for (int i = 0; i < rule_storage->curr_rule_count; ++i) {
        free(rule_storage->rules[i]);
    }
    free(rule_storage->rules);
}

static int RuleStorageExtendCapacity(RuleStorage *rule_storage) {
    SCEnter();
    RuleStorage *tmp_storage;

    rule_storage->max_rule_count = 2 * rule_storage->max_rule_count;

    tmp_storage = SCRealloc(rule_storage->rules, rule_storage->max_rule_count);
    if (tmp_storage == NULL) {
        RuleStorageFree(rule_storage);
        SCReturnInt(-1);        
    }
    rule_storage = tmp_storage; 
    SCReturnInt(0);
}

static int RuleStorageAddRule(RuleStorage *rule_storage, const char *rule) {
    SCEnter();
    int retval;

    rule_storage->rules[rule_storage->curr_rule_count] = SCMalloc((strlen(rule) + 1) * sizeof(char));
    if (rule_storage->rules[rule_storage->curr_rule_count] == NULL) {
        RuleStorageFree(rule_storage);
        SCReturnInt(-1);
    }
    strcpy(rule_storage->rules[rule_storage->curr_rule_count], rule);
    rule_storage->curr_rule_count++;
    if (rule_storage->curr_rule_count == rule_storage->max_rule_count) {
        retval = RuleStorageExtendCapacity(rule_storage);
        if (retval != 0) {
            SCReturnInt(retval);
        }
    }
    SCReturnInt(0);
}

static int RuleStorageSetup(RuleStorage *rule_storage) {
    SCEnter();
    rule_storage->curr_rule_count = 0;
    rule_storage->max_rule_count = 5;
    SCLogInfo("rule counts assigned");
    rule_storage->rules = SCMalloc(rule_storage->max_rule_count * sizeof(char *));

    if (rule_storage == NULL) {
        SCReturn(-1);
    }
    SCReturn(0);
}

int ConfigLoadRTEFlowRules(ConfNode *if_root, ConfNode *if_default, const char *filter_type, DPDKIfaceConfig *iconf) {
    SCEnter();
    ConfNode *node;
    RuleStorage rule_storage = {0};

    node = ConfNodeLookupChild(if_root, filter_type);
    if (node == NULL) {
        SCLogInfo("unable to find %s", filter_type);
    } else {
        ConfNode *rule_node;
        const char *rule;
        int retval;
        SCLogInfo("Trying to load rules");
        retval = RuleStorageSetup(&rule_storage);
        if (retval != 0) {
            SCReturn(retval);
        }
    
        TAILQ_FOREACH(rule_node, &node->head, next) {
            if (strcmp(rule_node->val, "rule") == 0) {

                ConfGetChildValueWithDefault(rule_node, if_default, "rule", &rule);
                SCLogInfo("found %s rule %s", filter_type, rule);
                RuleStorageAddRule(&rule_storage, rule);
            }
        }

    }
    
    if (strcmp(filter_type, "drop-filter") == 0) {
        iconf->drop_filter.rules = rule_storage.rules;
        iconf->drop_filter.curr_rule_count = rule_storage.curr_rule_count;
        iconf->drop_filter.max_rule_count = rule_storage.max_rule_count;
        SCLogInfo("number or rules %i", rule_storage.curr_rule_count);
    } else if (strcmp(filter_type, "allow-filter") == 0) {
        iconf->allow_filter.rules = rule_storage.rules;
    }
    SCReturnInt(0);
}


int CreateRules(int port_id, RuleStorage *rule_storage) {
    SCLogInfo("Entering CreateRules");
    //SCLogInfo("number or rules %i", rule_storage->curr_rule_count);
    for (int i = 0; i < rule_storage->curr_rule_count; i++) {
        struct rte_flow_item *items;
        struct rte_flow_attr attr = { 0 };
        struct rte_flow_action action[] = { { 0 }, { 0 } };
        struct rte_flow *flow;
        struct rte_flow_error flow_error = { 0 };
    
        attr.ingress = 1;
        action->type = RTE_FLOW_ACTION_TYPE_DROP;
        SCLogInfo("Entering ParsePattern");
        ParsePattern(rule_storage->rules[i], &items);

        int i = 0;
        while (items[i].type != RTE_FLOW_ITEM_TYPE_END) {
            i++;
            SCLogInfo("item num: %i", items[i].type);
        }
        flow = rte_flow_create(port_id, &attr, items, action, &flow_error);

        if (flow == NULL) {
            SCLogError("Error when creating rte_flow rule on: %s", flow_error.message);
            int ret = rte_flow_validate(port_id, &attr, items, action, &flow_error);
            SCLogError("Error on rte_flow validation for port: %s errmsg: %s",
                    rte_strerror(-ret), flow_error.message);
            return ret;
        } else {
            SCLogInfo("RTE_FLOW flow rule created for port ");
        }
    }
    RuleStorageFree(rule_storage);

    return 0;
}
// static int CountCharOccurence(const char* string, char pattern) {
//     int pattern_count;
//     char curr_ch;
//     while (curr_ch != '\0') {
//         if (curr_ch == pattern) {
//             pattern_count++;
//         }
//     }
//     return pattern_count;
// }

// static char* ClearRule(char **tokens, int tokens_count) {
//     int white_space_count;
//     for (int i = 0; i < tokens_count; ++i) {
//         white_space_count = CountCharOccurence(tokens[i], ' ');
//         if (white_space_count > 2) {
//             ParseItemWithSpec(tokens[i]);
//         } else {
//             ParseItemSimple(tokens[i]);
//         }
//         // check dpdk-testpmd source code for parsing patterns
//     }
// }

// static void* TokenizeRules(RuleStorage *rule_storage) {
//     char *rule;
//     int max_tokens;

//     for (int i = 0; i < rule_storage->curr_rule_count; ++i) {
//         rule = rule_storage->rules[i];
//         max_tokens = CountCharOccurence(rule, '/') + 1;
//         char *tokens[max_tokens];
//         rte_strsplit(rule, strlen(rule), tokens, max_tokens, '/');
        
//     }

// }

#endif /* HAVE_DPDK */
/**
 * @}
 */
