/* Copyright (C) 2021 Open Information Security Foundation
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
 * \author Adam Kiripolsky <adamkiripolsky.official@gmail.com>
 *
 * DPDK driver's helper functions
 *
 */

#include "util-dpdk-mlx5.h"
#include "util-dpdk.h"
#include "util-dpdk-rss.h"
#include "util-debug.h"
#include "util-dpdk-bonding.h"

#ifdef HAVE_DPDK

#define MLX5_RSS_HKEY_LEN 40

// void mlx5DeviceSetRSSHashFunction(uint64_t *rss_hf)
// {
//     *rss_hf = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_IPV6 | RTE_ETH_RSS_IPV6_EX;
// }

static int mlx5DeviceSetRSSFlowIPv4(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    int ret = 0;

    ret |= DeviceSetRSSFlowIPv4(port_id, port_name, rss_conf, nb_rx_queues);
    ret |= DeviceSetRSSFlowIPv4UDP(port_id, port_name, rss_conf, nb_rx_queues);
    ret |= DeviceSetRSSFlowIPv4TCP(port_id, port_name, rss_conf, nb_rx_queues);

    return ret;
}

static int mlx5DeviceSetRSSFlowIPv6(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    int ret = 0;

    ret |= DeviceSetRSSFlowIPv6(port_id, port_name, rss_conf, nb_rx_queues);
    ret |= DeviceSetRSSFlowIPv6UDP(port_id, port_name, rss_conf, nb_rx_queues);
    ret |= DeviceSetRSSFlowIPv6TCP(port_id, port_name, rss_conf, nb_rx_queues);

    return ret;
}

static int mlx5DeviceSetRSSWithFlows(int port_id, const char *port_name, int nb_rx_queues)
{
    int retval;
    uint8_t rss_key[MLX5_RSS_HKEY_LEN];
    struct rte_flow_error flush_error = { 0 };
    struct rte_eth_rss_conf rss_conf = {
        .rss_key = rss_key,
        .rss_key_len = MLX5_RSS_HKEY_LEN,
    };

    retval = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
    if (retval != 0) {
        SCLogError("Unable to get RSS hash configuration of port %s", port_name);
        return retval;
    }

    retval = 0;
    //retval |= DeviceSetRSSFlowQueues(port_id, port_name, rss_conf, nb_rx_queues);
    retval |= mlx5DeviceSetRSSFlowIPv4(port_id, port_name, rss_conf, nb_rx_queues);
    retval |= mlx5DeviceSetRSSFlowIPv6(port_id, port_name, rss_conf, nb_rx_queues);
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

int mlx5DeviceSetRSS(int port_id, int nb_rx_queues)
{
    int retval;
    (void)nb_rx_queues; // avoid unused variable warnings
    char port_name[RTE_ETH_NAME_MAX_LEN];

    retval = rte_eth_dev_get_name_by_port(port_id, port_name);
    if (unlikely(retval != 0)) {
        SCLogError("Failed to convert port id %d to the interface name: %s", port_id,
                strerror(-retval));
        return retval;
    }

    mlx5DeviceSetRSSWithFlows(port_id, port_name, nb_rx_queues);

    return 0;
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
