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
 * \author Adam Kiripolsky <adamkiripolsky.official@gmail.com>
 *
 * DPDK rte_flow RSS helper functions
 *
 */

#include "util-dpdk-rss.h"
#include "util-dpdk.h"
#include "util-debug.h"
#include "util-dpdk-bonding.h"

#ifdef HAVE_DPDK

int DeviceSetRSSFlowQueues(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    struct rte_flow_action_rss rss_action_conf = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 } };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow *flow;
    struct rte_flow_error flow_error = { 0 };
    uint16_t queues[RTE_MAX_QUEUES_PER_PORT];

    for (int i = 0; i < nb_rx_queues; ++i)
        queues[i] = i;

    rss_action_conf.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
    rss_action_conf.level = 0;
    rss_action_conf.types = 0; // queues region can not be configured with types
    rss_action_conf.key_len = 0;
    rss_action_conf.key = NULL;

    if (nb_rx_queues < 1) {
        FatalError("The number of queues for RSS configuration must be "
                   "configured with a positive number");
    }

    rss_action_conf.queue_num = nb_rx_queues;
    rss_action_conf.queue = queues;

    attr.ingress = 1;
    pattern[0].type = RTE_FLOW_ITEM_TYPE_END;
    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_action_conf;
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

int DeviceCreateRSSFlow(int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf,
        uint64_t rss_type, struct rte_flow_item *pattern, int nb_rx_queues)
{
    struct rte_flow_action_rss rss_action_conf = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow *flow;
    struct rte_flow_error flow_error = { 0 };

    rss_action_conf.func = RTE_ETH_HASH_FUNCTION_TOEPLITZ;
    rss_action_conf.level = 0;
    rss_action_conf.types = rss_type;
    rss_action_conf.key_len = rss_conf.rss_key_len;
    rss_action_conf.key = rss_conf.rss_key;
    uint16_t queues[RTE_MAX_QUEUES_PER_PORT];

    for (int i = 0; i < nb_rx_queues; ++i)
        queues[i] = i;

    rss_action_conf.queue_num = nb_rx_queues;
    rss_action_conf.queue = queues;

    attr.ingress = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_action_conf;
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

int DeviceSetRSSFlowIPv4(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }};

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DeviceCreateRSSFlow(
            port_id, port_name, rss_conf, RTE_ETH_RSS_NONFRAG_IPV4_OTHER, pattern, nb_rx_queues);

    return ret;
}

int DeviceSetRSSFlowIPv4UDP(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DeviceCreateRSSFlow(
            port_id, port_name, rss_conf, RTE_ETH_RSS_NONFRAG_IPV4_UDP, pattern, nb_rx_queues);

    return ret;
}

int DeviceSetRSSFlowIPv4TCP(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DeviceCreateRSSFlow(
            port_id, port_name, rss_conf, RTE_ETH_RSS_NONFRAG_IPV4_TCP, pattern, nb_rx_queues);

    return ret;
}

int DeviceSetRSSFlowIPv4SCTP(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_SCTP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DeviceCreateRSSFlow(
            port_id, port_name, rss_conf, RTE_ETH_RSS_NONFRAG_IPV4_SCTP, pattern, nb_rx_queues);

    return ret;
}

int DeviceSetRSSFlowIPv4Frag(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DeviceCreateRSSFlow(
            port_id, port_name, rss_conf, RTE_ETH_RSS_FRAG_IPV4, pattern, nb_rx_queues);

    return ret;
}

int DeviceSetRSSFlowIPv6(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }};

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DeviceCreateRSSFlow(
            port_id, port_name, rss_conf, RTE_ETH_RSS_NONFRAG_IPV6_OTHER, pattern, nb_rx_queues);

    return ret;
}

int DeviceSetRSSFlowIPv6UDP(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DeviceCreateRSSFlow(
            port_id, port_name, rss_conf, RTE_ETH_RSS_NONFRAG_IPV6_UDP, pattern, nb_rx_queues);

    return ret;
}

int DeviceSetRSSFlowIPv6TCP(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DeviceCreateRSSFlow(
            port_id, port_name, rss_conf, RTE_ETH_RSS_NONFRAG_IPV6_TCP, pattern, nb_rx_queues);

    return ret;
}

int DeviceSetRSSFlowIPv6SCTP(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_SCTP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DeviceCreateRSSFlow(
            port_id, port_name, rss_conf, RTE_ETH_RSS_NONFRAG_IPV6_SCTP, pattern, nb_rx_queues);

    return ret;
}

int DeviceSetRSSFlowIPv6Frag(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DeviceCreateRSSFlow(
        port_id, port_name, rss_conf, RTE_ETH_RSS_FRAG_IPV6, pattern, nb_rx_queues);

    return ret;
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
