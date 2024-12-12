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
 *  \defgroup dpdk DPDK NVIDIA mlx5 driver helpers functions
 *
 *  @{
 */

/**
 * \file
 *
 * \author Adam Kiripolsky <adam.kiripolsky@cesnet.cz>
 *
 * DPDK driver's helper functions
 *
 */

#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-bonding.h"
#include "util-dpdk-mlx5.h"
#include "util-dpdk-rss.h"

#ifdef HAVE_DPDK

#define MLX5_RSS_HKEY_LEN 40

static int mlx5DeviceDecap(int port_id, char *port_name, struct rte_flow_item *pattern, enum rte_flow_action_type decap_type) {
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };
    struct rte_flow_error flow_error = { 0 };
    struct rte_flow_action_jump jump_conf = { 0 };

    attr.ingress = 1;
    attr.group = 0;
    jump_conf.group = 1;

    action[0].type = decap_type;
    action[1].type = RTE_FLOW_ACTION_TYPE_JUMP;
    action[1].conf = &jump_conf;
    action[2].type = RTE_FLOW_ACTION_TYPE_END;

    struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow == NULL) {
        SCLogError("Error when creating rte_flow rule for vxlan offload on %s: %s", port_name, flow_error.message);
        int ret = rte_flow_validate(port_id, &attr, pattern, action, &flow_error);
        SCLogError("Error on rte_flow validation (vxlan offload) for port %s: %s errmsg: %s", port_name,
                rte_strerror(-ret), flow_error.message);
        return ret;
    } else {
        SCLogInfo("RTE_FLOW flow rule created for port %s", port_name);
    }

    SCReturnInt(0);
}

static int mlx5DeviceVxlanOffloadOuterIPv4(int port_id, char *port_name) {
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_VXLAN;
    pattern[4].type = RTE_FLOW_ITEM_TYPE_END;

    SCReturnInt(mlx5DeviceDecap(port_id, port_name, pattern, RTE_FLOW_ACTION_TYPE_VXLAN_DECAP));
}

static int mlx5DeviceVxlanOffloadOuterIPv6(int port_id, char *port_name) {
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_VXLAN;
    pattern[4].type = RTE_FLOW_ITEM_TYPE_END;

    SCReturnInt(mlx5DeviceDecap(port_id, port_name, pattern, RTE_FLOW_ACTION_TYPE_VXLAN_DECAP));
}

int mlx5DeviceSetRTEFlowOffloads(int port_id, char *port_name) {
    int ret = mlx5DeviceVxlanOffloadOuterIPv4(port_id, port_name);
    ret |= mlx5DeviceVxlanOffloadOuterIPv6(port_id, port_name);
    
    if (ret != 0) {
        struct rte_flow_error flush_error = { 0 };
        int retval = rte_flow_flush(port_id, &flush_error);
        if (retval != 0) {
            SCLogError("%s: unable to flush rte_flow rules: %s Flush error msg: %s",
                port_name, rte_strerror(-retval), flush_error.message);
        }
    }

    return ret;
}

int mlx5DeviceSetRSS(int port_id, int nb_rx_queues, char *port_name, bool decap_enabled)
{
    uint16_t queues[RTE_MAX_QUEUES_PER_PORT];
    struct rte_flow_error flush_error = { 0 };
    struct rte_eth_rss_conf rss_conf = {
        .rss_key = RSS_HKEY,
        .rss_key_len = MLX5_RSS_HKEY_LEN,
    };

    if (nb_rx_queues < 1) {
        FatalError("The number of queues for RSS configuration must be "
                   "configured with a positive number");
    }

    struct rte_flow_action_rss rss_action_conf = DeviceInitRSSAction(
            rss_conf, nb_rx_queues, queues, RTE_ETH_HASH_FUNCTION_TOEPLITZ, true);

    int retval = DeviceCreateRSSFlowGeneric(port_id, port_name, rss_action_conf, decap_enabled);
    if (retval != 0) {
        retval = rte_flow_flush(port_id, &flush_error);
        if (retval != 0) {
            SCLogError("Unable to flush rte_flow rules of %s: %s Flush error msg: %s", port_name,
                    rte_strerror(-retval), flush_error.message);
        }
        return retval;
    }

    return 0;
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
