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

int SetupRuleStorage(DPDKIfaceConfig *iconf) {
    iconf->allow_filter.curr_rule_count = 0;
    iconf->allow_filter.max_rule_count = 5;
    iconf->allow_filter.rules = malloc(iconf->allow_filter.max_rule_count * sizeof(char *));

    iconf->drop_filter.curr_rule_count = 0;
    iconf->drop_filter.max_rule_count = 5;
    iconf->drop_filter.rules = malloc(iconf->drop_filter.max_rule_count * sizeof(char *));
}

int ConfigLoadRTEFlowRules(ConfNode *if_root, ConfNode *if_default, const char *filter_type, DPDKIfaceConfig *iconf) {
    ConfNode *node;

    node = ConfNodeLookupChild(if_root, filter_type);
    if (node == NULL) {
        SCLogInfo("unable to find %s", filter_type);
    } else {
        ConfNode *rule_node;
        const char *rule;
        
        TAILQ_FOREACH(rule_node, &node->head, next) {
            if (strcmp(rule_node->val, "rule") == 0) {
                    ConfGetChildValueWithDefault(rule_node, if_default, "rule", &rule);
                    SCLogInfo("found %s rule %s", filter_type, rule);
                    if (strcmp(filter_type, "drop_filter") == 0) {
                        iconf->drop_filter.rules[iconf->drop_filter.curr_rule_count] = malloc((strlen(rule) + 1) * sizeof(char));
                        if (iconf->drop_filter.rules == NULL) {
                            SCReturn(-1);
                        }
                    } else {
                        iconf->allow_filter.rules[iconf->allow_filter.curr_rule_count] = malloc((strlen(rule) + 1) * sizeof(char));
                        if (iconf->allow_filter.rules == NULL) {
                            SCReturn(-1);
                    }
                    // realloc, rewrite code repeating --> one generalized function
                }
        }
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
