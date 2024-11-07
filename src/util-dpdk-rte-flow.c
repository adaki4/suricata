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
 * \author Adam Kiripolsky <adamkiripolsky.official@gmail.com>
 *
 * DPDK rte_flow rules util functions
 *
 */

#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-rte-flow.h"
#include "runmode-dpdk.h"

#ifdef HAVE_DPDK

int RuleStorageAddRule(RuleStorage *rule_storage, const char *rule) {
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

void RuleStorageFree(RuleStorage *rule_storage) {
    for (int i = 0; i < rule_storage->curr_rule_count; ++i) {
        free(rule_storage->rules[i]);
    }
    free(rule_storage->rules);
}

int RuleStorageExtendCapacity(RuleStorage *rule_storage) {
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

int RuleStorageSetup(RuleStorage *rule_storage) {
    SCEnter();
    rule_storage->curr_rule_count = 0;
    rule_storage->max_rule_count = 5;
    rule_storage->rules = SCMalloc(rule_storage->max_rule_count * sizeof(char *));

    if (rule_storage == NULL) {
        SCReturn(-1);
    }
    SCReturn(0);
}

int ConfigLoadRTEFlowRules(ConfNode *if_root, ConfNode *if_default, const char *filter_type, DPDKIfaceConfig *iconf) {
    SCEnter();
    ConfNode *node;
    RuleStorage *rule_storage;

    if (strcmp(filter_type, "drop_filter") == 0) {
        rule_storage = &iconf->drop_filter;
    } else if (strcmp(filter_type, "allow_filter") == 0) {
        rule_storage = &iconf->allow_filter;
    }
    node = ConfNodeLookupChild(if_root, filter_type);
    if (node == NULL) {
        SCLogInfo("unable to find %s", filter_type);
    } else {
        ConfNode *rule_node;
        const char *rule;
        int retval;
        
        retval = RuleStorageSetup(rule_storage);
        if (retval != 0) {
            SCReturn(retval);
        }
    
        TAILQ_FOREACH(rule_node, &node->head, next) {
            if (strcmp(rule_node->val, "rule") == 0) {

                ConfGetChildValueWithDefault(rule_node, if_default, "rule", &rule);
                SCLogInfo("found %s rule %s", filter_type, rule);
                RuleStorageAddRule(rule_storage, rule);
            }
        }
    }
    TokenizeRules(rule_storage);
    SCReturnInt(0);
}

static int CountCharOccurence(const char* string, char pattern) {
    int pattern_count;
    char curr_ch;
    while (curr_ch != '\0') {
        if (curr_ch == pattern) {
            pattern_count++;
        }
    }
    return pattern_count;
}

static char* ClearRule(char **tokens, int tokens_count) {
    int white_space_count;
    for (int i = 0; i < tokens_count; ++i) {
        white_space_count = CountCharOccurence(tokens[i], ' ');
        if (white_space_count > 2) {
            ParseItemWithSpec(tokens[i]);
        } else {
            ParseItemSimple(tokens[i]);
        }
        // check dpdk-testpmd source code for parsing patterns
    }
}

static void* TokenizeRules(RuleStorage *rule_storage) {
    char *rule;
    int max_tokens;

    for (int i = 0; i < rule_storage->curr_rule_count; ++i) {
        rule = rule_storage->rules[i];
        max_tokens = CountCharOccurence(rule, '/') + 1;
        char *tokens[max_tokens];
        rte_strsplit(rule, strlen(rule), tokens, max_tokens, '/');
        
    }

}

static void PortSetL3AdressFilter() {
}

static void PortSetL4PortFilter() {

}

#endif /* HAVE_DPDK */
/**
 * @}
 */
