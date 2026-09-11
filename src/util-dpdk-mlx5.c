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
#include "decode.h"
#include "util-dpdk.h"
#include "util-dpdk-bonding.h"
#include "util-dpdk-mlx5.h"
#include "util-dpdk-rss.h"
#include "util-dpdk-rte-flow.h"

#ifdef HAVE_DPDK

#define MLX5_RSS_HKEY_LEN 40

static int mlx5DeviceSetRSS(int, uint16_t, char *, uint16_t, RteFlowBypassData *);

int mlx5DevicePostStartActions(
        int port_id, uint16_t nb_rx_queues, char *port_name, bool capture_bypass_enabled, RteFlowBypassData *rte_flow_bypass_data)
{
    int retval = 0;
    if (capture_bypass_enabled) {
        retval = mlx5DeviceSetRSS(port_id, nb_rx_queues, port_name, RTE_JUMP_GROUP, rte_flow_bypass_data);
    } else {
        retval = mlx5DeviceSetRSS(port_id, nb_rx_queues, port_name, RTE_DEFAULT_GROUP, rte_flow_bypass_data);
    }
    retval += RteFlowCreateJumpRule(port_id, port_name, rte_flow_bypass_data);
    return retval;
}

static int mlx5DeviceSetRSS(int port_id, uint16_t nb_rx_queues, char *port_name, uint16_t group, RteFlowBypassData *rte_flow_bypass_data)
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

    struct rte_flow_action_rss rss_action_conf =
            DPDKInitRSSAction(rss_conf, nb_rx_queues, queues, RTE_ETH_HASH_FUNCTION_TOEPLITZ, true);
    int retval = 0;
    // Change if async
    if (true) {
        retval = DPDKCreateRSSFlowAsync(port_id, port_name, rss_action_conf, group, rte_flow_bypass_data);
    } else {
        retval = DPDKCreateRSSFlowGeneric(port_id, port_name, rss_action_conf, group);
    }
    if (retval != 0) {
        retval = rte_flow_flush(port_id, &flush_error);
        if (retval != 0) {
            SCLogError("%s: unable to flush rte_flow rules: %s Flush error msg: %s", port_name,
                    rte_strerror(-retval), flush_error.message);
        }
        return retval;
    }

    return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

int mlx5DeviceRteFlowTemplatesInit(uint16_t port_id, uint16_t queues_nb, const char *port_name, RteFlowBypassData *rte_flow_bypass_data) 
{
    SCEnter();
    struct rte_flow_port_attr port_attr = { 0 };
    struct rte_flow_queue_attr queue_attr = {
        .size = queues_nb,
    };

    /* Create as many queues as there are workers and additional 1 for flow manager and 1 for bypass manager */
    const struct rte_flow_queue_attr *queue_attrs[queues_nb];
    for (uint16_t i = 0; i < queues_nb; i++) {
        queue_attrs[i] = &queue_attr;
    }

    struct rte_flow_error flow_error = { 0 };
    int retval = rte_flow_configure(
        port_id, &port_attr, queues_nb, queue_attrs, &flow_error);
    if (retval < 0) { 
        SCLogError("%s: rte_flow_configure failed: %s", port_name, flow_error.message);
        SCReturnInt(retval);
    }

    /* Prepare template resources */
    retval = RteFlowBypassTemplateResourcesInit(port_id, rte_flow_bypass_data);
    if (retval != 0)
        SCReturnInt(retval);
    retval = RteFlowJumpRuleTemplateInit(port_id, rte_flow_bypass_data);
    if (retval != 0)
        SCReturnInt(retval);
    retval = DPDKInitRSSTemplate(port_id, rte_flow_bypass_data);
    if (retval < 0) {
        SCReturnInt(retval);
    }
    SCReturnInt(0);
}

int mlx5DeviceRteFlowUpdateStats(uint16_t queue_id, RteFlowHandlerToFlow *flow_handler_info)
{
    struct rte_flow_op_attr op_attr = { .postpone = 1 };
    struct rte_flow_query_count query_count = { 0 };
    struct rte_flow_error error;
    uint64_t src_packets = 0, src_bytes = 0, dst_packets = 0, dst_bytes = 0;
    RteFlowBypassData *bypass_data = flow_handler_info->rte_flow_bypass_data;
    uint16_t port_id = bypass_data->port_id;

    query_count.reset = 1;
	int retval = rte_flow_async_action_handle_query(port_id, queue_id, &op_attr,
										 flow_handler_info->src_action_handle, &query_count, flow_handler_info, &error);
	if (retval != 0) {
		SCLogWarning("rte_flow_async_action_handle_query() failed: %d with: %s\n", retval, error.message);
        SC_ATOMIC_ADD(bypass_data->rte_bypass_query_error, 1);
    } else {
        src_packets += query_count.hits;
        src_bytes += query_count.bytes;
    }

    memset(&query_count, 0, sizeof(struct rte_flow_query_count));
    query_count.reset = 1;

    retval = rte_flow_async_action_handle_query(port_id, queue_id, &op_attr,
										 flow_handler_info->dst_action_handle, &query_count, flow_handler_info, &error);
    if (retval != 0)  {
        SCLogWarning("rte_flow_async_action_handle_query() failed: %d with: %s\n", retval, error.message);
        SC_ATOMIC_ADD(bypass_data->rte_bypass_query_error, 1);
    } else {
        dst_packets += query_count.hits;
        dst_bytes += query_count.bytes;
    }

    retval = rte_flow_push(port_id, queue_id, &error);
    if (retval != 0) {
        SCLogWarning("UpdateStats rte_flow_push() failed: %s", error.message);
    }

    int max_res_size = 1024;
    struct rte_flow_op_result res[max_res_size];
    retval = rte_flow_pull(port_id, queue_id, res, max_res_size, &error);
    if (retval < 0) {
        SCLogWarning("UpdateStats rte_flow_pull() failed: %s", error.message);
    } else {
        for (int i = 0; i < retval; i++) {
            if (res[i].status != 0 && res[i].user_data != NULL) {
                SCLogWarning("UpdateStats rte_flow_pull Not OK: status=%d user_data=%p", res[i].status, res[i].user_data);
            }
        }
    }

    return 0;
}

struct rte_flow_action_list_handle *mlx5DeviceRteFlowCreateIndirectAction(uint16_t port_id, uint32_t queue_id, RteFlowHandlerToFlow *flow_handler_info)
{
    // TODO
    return NULL;
}

void mlx5DeviceRteFlowRuleDestroy(uint16_t queue_id, RteFlowHandlerToFlow *flow_handler_info)
{
    // TODO copy from other branch
}

int mlx5DeviceRteFlowBypassCallback(Packet *p)
{
    // TODO copy from other branch
    SCReturnInt(1);
}


#pragma GCC diagnostic pop

#endif /* HAVE_DPDK */
/**
 * @}
 */
