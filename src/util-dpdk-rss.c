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
 *  \defgroup dpdk DPDK rte_flow RSS  helpers functions
 *
 *  @{
 */

/**
 * \file
 *
 * \author Adam Kiripolsky <adam.kiripolsky@cesnet.cz>
 *
 * DPDK rte_flow RSS helper functions
 *
 */

#include "util-dpdk-rss.h"
#include "util-dpdk.h"
#include "util-debug.h"

#ifdef HAVE_DPDK

struct rte_flow_action_rss DeviceInitRSSAction(struct rte_eth_rss_conf rss_conf, int nb_rx_queues,
        uint16_t *queues, enum rte_eth_hash_function func, bool set_key)
{
    struct rte_flow_action_rss rss_action_conf = { 0 };
    rss_action_conf.func = func;
    rss_action_conf.level = 0;

    if (set_key) {
        rss_action_conf.key = rss_conf.rss_key;
        rss_action_conf.key_len = rss_conf.rss_key_len;
    } else {
        rss_action_conf.key_len = 0;
    }

    if (nb_rx_queues != 0) {
        for (int i = 0; i < nb_rx_queues; ++i)
            queues[i] = i;

        rss_action_conf.queue = queues;
    }
    rss_action_conf.queue_num = nb_rx_queues;

    return rss_action_conf;
}

int DeviceCreateRSSFlowUniform(
        int port_id, const char *port_name, struct rte_flow_action_rss rss_conf)
{
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow *flow;
    struct rte_flow_error flow_error = { 0 };
    struct rte_flow_item pattern[] = { { 0 } };

    rss_conf.types = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_IPV6;

    attr.ingress = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_conf;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    pattern[0].type = RTE_FLOW_ITEM_TYPE_END;

    flow = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow == NULL) {
        SCLogError("Error when creating rte_flow rule on %s: %s", port_name, flow_error.message);
        int ret = rte_flow_validate(port_id, &attr, pattern, action, &flow_error);
        SCLogError("Error on rte_flow validation for port %s: %s errmsg: %s", port_name,
                rte_strerror(-ret), flow_error.message);
        return ret;
    } else {
        SCLogInfo("RTE_FLOW flow rule created for port %s", port_name);
    }

    return 0;
}

static int DeviceCreateRSSFlow(int port_id, const char *port_name,
        struct rte_flow_action_rss rss_conf, uint64_t rss_type, struct rte_flow_item *pattern)
{
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow *flow;
    struct rte_flow_error flow_error = { 0 };

    rss_conf.types = rss_type;

    attr.ingress = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_conf;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    flow = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow == NULL) {
        SCLogError("Error when creating rte_flow rule on %s: %s", port_name, flow_error.message);
        int ret = rte_flow_validate(port_id, &attr, pattern, action, &flow_error);
        SCLogError("Error on rte_flow validation for port %s: %s errmsg: %s", port_name,
                rte_strerror(-ret), flow_error.message);
        return ret;
    } else {
        SCLogInfo("RTE_FLOW flow rule created for port %s", port_name);
    }

    return 0;
}

/**
 * @brief Some drivers (mostly for intel NICs) require specific way of setting RTE_FLOW RSS rules
 * with one rule that sets up only queues and other rules that specify patterns to match with
 * queues configured.
 */

int DeviceSetRSSFlowQueues(int port_id, const char *port_name, struct rte_flow_action_rss rss_conf)
{
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 } };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow *flow;
    struct rte_flow_error flow_error = { 0 };

    rss_conf.types = 0; // queues region can not be configured with types

    attr.ingress = 1;
    pattern[0].type = RTE_FLOW_ITEM_TYPE_END;
    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_conf;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    flow = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow == NULL) {
        SCLogError("Error when creating rte_flow rule on %s: %s", port_name, flow_error.message);
        int ret = rte_flow_validate(port_id, &attr, pattern, action, &flow_error);
        SCLogError("Error on rte_flow validation for port %s: %s errmsg: %s", port_name,
                rte_strerror(-ret), flow_error.message);
        return ret;
    } else {
        SCLogInfo("RTE_FLOW queue region created for port %s", port_name);
    }
    return 0;
}

int DeviceSetRSSFlowIPv4(int port_id, const char *port_name, struct rte_flow_action_rss rss_conf)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DeviceCreateRSSFlow(port_id, port_name, rss_conf, RTE_ETH_RSS_IPV4, pattern);

    return ret;
}

int DeviceSetRSSFlowIPv6(int port_id, const char *port_name, struct rte_flow_action_rss rss_conf)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DeviceCreateRSSFlow(port_id, port_name, rss_conf, RTE_ETH_RSS_IPV6, pattern);

    return ret;
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
