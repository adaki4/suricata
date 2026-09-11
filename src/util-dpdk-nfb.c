/* Copyright (C) 2026 Open Information Security Foundation
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
 *  \defgroup dpdk DPDK NVIDIA nfb driver helpers functions
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

#include "flow-storage.h"  
#include "util-debug.h"
#include "util-device-private.h"
#include "util-dpdk.h"
#include "util-dpdk-bonding.h"
#include "util-dpdk-nfb.h"
#include "util-dpdk-rss.h"
#include "util-dpdk-rte-flow.h"
#include "util-dpdk-rss.h"

#include "tm-threads.h"

#ifdef HAVE_DPDK

#define NFB_RSS_HKEY_LEN 40
#define NFB_FLOW_QUEUE_SZ 1024 //1048576

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static struct rte_flow_action_list_handle *nfbDeviceRteFlowCreateIndirectAction(uint16_t, RteFlowHandlerToFlow *);

static const struct rte_flow_action indir_handle_actions[] = {
	{ .type = RTE_FLOW_ACTION_TYPE_CONNTRACK },
	{ .type = RTE_FLOW_ACTION_TYPE_COUNT },
	{ .type = RTE_FLOW_ACTION_TYPE_COUNT },
	{ .type = RTE_FLOW_ACTION_TYPE_END },
};


void nfbDeviceSetRSSConf(struct rte_eth_rss_conf *rss_conf) 
{
    rss_conf->rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;
    rss_conf->rss_key = NULL;
}

int nfbDeviceRteFlowTemplatesInit(uint16_t port_id, uint16_t queues_nb, const char *port_name, RteFlowBypassData *rte_flow_bypass_data)
{
    SCEnter();
    struct rte_flow_port_attr port_attr = { 0 };
    struct rte_flow_queue_attr queue_attr = {
        .size = NFB_FLOW_QUEUE_SZ,
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

    SCReturnInt(0);
}

int nfbDeviceRteFlowUpdateStats(uint16_t queue_id, RteFlowHandlerToFlow *flow_handler_info)
{
    struct rte_flow_op_attr op_attr = { .postpone = 0 };
    struct rte_flow_error flow_error = { 0 };
    uint16_t port_id = flow_handler_info->rte_flow_bypass_data->port_id;

    int retval = rte_flow_async_action_list_handle_query_update(port_id, queue_id, &op_attr, flow_handler_info->src_action_list_handle, NULL, flow_handler_info->query, RTE_FLOW_QU_QUERY_FIRST, flow_handler_info, &flow_error);
    if (retval < 0) {
        SCLogWarning("nfb rte_flow_async_action_list_handle_query_update() error: %s",
                flow_error.message ? flow_error.message : "unknown error");
        SCReturnInt(0);
    }
    retval = rte_flow_push(port_id, queue_id, &flow_error);
    if (retval < 0) {
        SCLogError("rte_flow_push() failed: %s",
                 flow_error.message ? flow_error.message : "unknown error");
    }

    const uint16_t pull_size = 16;
    struct rte_flow_op_result results[pull_size];
    int loops = 0;
    do {
        int pulled = rte_flow_pull(port_id, queue_id, results, pull_size, &flow_error);
        if (pulled < 0) {
            SCLogWarning("nfb rte_flow_pull() error: %s",
                    flow_error.message ? flow_error.message : "unknown error");
            break;
        }
        for (int i = 0; i < pulled; i++) {
            if (results[i].user_data != flow_handler_info)
                continue;
            if (results[i].status != RTE_FLOW_OP_SUCCESS) {
                SCLogWarning("nfb query op not success (status=%d)", results[i].status);
                SCReturnInt(0);
            }
            /* The hardware has written the counters into our query[] buffers
             * (count_src = query[1], count_dst = query[2]) at pull time. */
            if (flow_handler_info->count_src.hits || flow_handler_info->count_dst.hits) {
                SCReturnInt(1);
            }
            SCReturnInt(0);
        }
        if (pulled == pull_size) {
            /* More completions may be queued - keep pulling to find ours. */
            continue;
        }
        /* Queue drained without finding our completion; try a few more times */
        loops++;
        if (loops < 60) {
            rte_delay_us(100);
        }
    } while (loops < 60);

    SCReturnInt(0);
}

struct rte_flow_action_list_handle *nfbDeviceRteFlowCreateIndirectAction(uint16_t port_id, RteFlowHandlerToFlow *flow_handler_info)
{
    struct rte_flow_error flow_error = { 0 };
	struct rte_flow_indir_action_conf indir_conf = { .ingress = 1 };

	struct rte_flow_action_list_handle *handle = rte_flow_action_list_handle_create(
		port_id, &indir_conf, indir_handle_actions, &flow_error);

	if (!handle)
		SCLogError("rte_flow_async_action_handle_create() failed: %s\n", flow_error.message);

    return handle;
}

void nfbDeviceRteFlowRuleDestroy(uint16_t queue_id, RteFlowHandlerToFlow *flow_handler_info)
{
    const struct rte_flow_op_attr op_attr = { .postpone = 0 };
    int retval = 0;
    struct rte_flow_error flow_error = { 0 };
    uint16_t port_id = flow_handler_info->rte_flow_bypass_data->port_id;
    if (flow_handler_info->src_action_list_handle != NULL) {
        retval = rte_flow_action_list_handle_destroy(port_id, flow_handler_info->src_action_list_handle, &flow_error);
        if (retval != 0) {
            SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                    rte_strerror(-retval), flow_error.message);
            }
    }
    if (flow_handler_info->src_handle != NULL) {
        retval = rte_flow_async_destroy(port_id, queue_id, &op_attr, flow_handler_info->src_handle, (void *)flow_handler_info, &flow_error);
        if (retval != 0) {
            SCLogError("rte_flow dynamic bypass: destroy rte_flow rule error %s errmsg: %s",
                    rte_strerror(-retval), flow_error.message);
        }
    }

    retval = rte_flow_push(port_id, queue_id, &flow_error);
    if (retval < 0) { 
			SCLogError("rte_flow_push() failed: %s",
				 flow_error.message ? flow_error.message : "unknown error");
	}

    const int max_res_size = 1024;
    struct rte_flow_op_result res[max_res_size];
    int pulled = 0, loops = 0;
    while (pulled == 0 && loops < 60) {
        pulled = rte_flow_pull(port_id, queue_id, res, max_res_size, &flow_error);
        if (pulled < 0) {
            SCLogWarning("rte_flow bypass: worker pull failed on queue %u: %s",
                    queue_id, flow_error.message);
            break;
        }
        for (int i = 0; i < pulled; i++) {
            if (res[i].status != 0 && res[i].user_data != NULL) {
                RteFlowHandlerToFlow *flow_handler_info =
                        (RteFlowHandlerToFlow *)res[i].user_data;
            }
        }
        loops++;
    }

}

/** \brief Create hardware (rte_flow) rule for the incomign flow.  
 * 
 * \param p packet for which we create the bypass
 * \return 1 if the hardware rule was created succesfully, 0 otherwise
*/
int nfbDeviceRteFlowBypassCallback(Packet *p)
{
    Flow *flow = p->flow;
    DPDKDeviceResources *dpdk_vars = LiveDeviceGetById(flow->livedev_id)->dpdk_vars;
    RteFlowBypassData *bypass_data = dpdk_vars->rte_flow_bypass_data;
    FlowBypassInfo *fc = SCFlowGetStorageById(flow, GetFlowBypassInfoID());
    RteFlowHandlerToFlow *flow_handler_info;
    if (fc == NULL) {
        SCReturnInt(0);
    }
    if (fc->bypass_data != NULL) {
        SCReturnInt(0);
    }
    if (rte_mempool_get(bypass_data->bypass_info_mp,
                (void **)&flow_handler_info) < 0) {
        SC_ATOMIC_ADD(bypass_data->rte_bypass_mempool_info_get_error, 1);
        SCReturnInt(0);
    }
    fc->bypass_data = flow_handler_info;
    flow_handler_info->rte_flow_bypass_data = bypass_data;

   /* Bypass rules pattern template setup */
    struct rte_flow_item_ipv4 ipv4_spec = { 0 }, ipv4_mask = { 0 };
    struct rte_flow_item_ipv6 ipv6_spec = { 0 }, ipv6_mask = { 0 };
    struct rte_flow_item_tcp tcp_spec = { 0 }, tcp_mask = { 0 };
    struct rte_flow_item_udp udp_spec = { 0 }, udp_mask = { 0 };
    /* vlan_spec/vlan_mask must live for the whole function: their addresses are
     * referenced by items[VLAN_INDEX] and dereferenced by rte_flow_async_create()
     * inside RteFlowCreateRuleAsync(). Keeping them at block scope would leave
     * dangling stack pointers (use-after-scope) and crash the PMD. */
    struct rte_flow_item_vlan vlan_spec = { 0 }, vlan_mask = { 0 };

    struct rte_flow_item items[] = { { 0 }, { 0 }, { 0 }, { 0 }, { 0 } };
    struct rte_flow_action action[] = { { 0 }, { 0 }, { 0 } };

    void *ip_spec = NULL, *ip_mask = NULL, *l4_spec = NULL, *l4_mask = NULL;
    RteFlowTemplateResources *bypass_resources = NULL;

    uint16_t port_id = dpdk_vars->port_id;
    uint8_t pattern_template_index = RteGetTemplatePatternIndex(flow->vlan_idx > 0, flow->proto == IPPROTO_TCP);
    uint16_t rule_queue_id = p->dpdk_v.in_queue_id;

    items[L2_INDEX].type = RTE_FLOW_ITEM_TYPE_ETH;
    items[END_INDEX].type = RTE_FLOW_ITEM_TYPE_END;

    action[0].type = RTE_FLOW_ACTION_TYPE_INDIRECT_LIST;
    action[1].type = RTE_FLOW_ACTION_TYPE_DROP;
    action[2].type = RTE_FLOW_ACTION_TYPE_END;

    if (flow->vlan_idx) {
        /* Mask only the 12 VLAN ID bits (0xFFF), matching rte_flow_item_vlan_mask
         * used by the VLAN pattern templates. */
        vlan_spec.hdr.vlan_tci = flow->vlan_id[0];
        vlan_mask.hdr.vlan_tci = 0x0FFF;
        items[VLAN_INDEX].type = RTE_FLOW_ITEM_TYPE_VLAN;
        items[VLAN_INDEX].spec = &vlan_spec;
        items[VLAN_INDEX].mask = &vlan_mask;
    } else {
        items[VLAN_INDEX].type = RTE_FLOW_ITEM_TYPE_VOID;
    }

    if (FLOW_IS_IPV4(flow)) {
        bypass_resources = bypass_data->bypass_resources_ipv4;    
        SCLogDebug("Add an IPv4 rte_flow bypass rule");
        ipv4_spec.hdr.src_addr = flow->src.address.address_un_data32[0];
        ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
        ipv4_spec.hdr.dst_addr = flow->dst.address.address_un_data32[0];
        ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
        ip_spec = &ipv4_spec;
        ip_mask = &ipv4_mask;
        items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV4;
    } else {
        bypass_resources = bypass_data->bypass_resources_ipv6;
#if RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0)
        SCLogDebug("Add an IPv6 rte_flow bypass rule");
        memcpy(ipv6_spec.hdr.src_addr.a, flow->src.address.address_un_data8, 16);
        memset(ipv6_mask.hdr.src_addr.a, 0xFF, 16);
        memcpy(ipv6_spec.hdr.dst_addr.a, flow->dst.address.address_un_data8, 16);
        memset(ipv6_mask.hdr.dst_addr.a, 0xFF, 16);
#else
        SCLogDebug("Add an IPv6 rte_flow bypass rule");
        memcpy(ipv6_spec.hdr.src_addr, flow->src.address.address_un_data8, 16);
        memset(ipv6_mask.hdr.src_addr, 0xFF, 16);
        memcpy(ipv6_spec.hdr.dst_addr, flow->dst.address.address_un_data8, 16);
        memset(ipv6_mask.hdr.dst_addr, 0xFF, 16);
#endif /* RTE_VERSION >= RTE_VERSION_NUM(24, 0, 0, 0) */
        ip_spec = &ipv6_spec;
        ip_mask = &ipv6_mask;
        items[L3_INDEX].type = RTE_FLOW_ITEM_TYPE_IPV6;
    }

    if (flow->proto == IPPROTO_TCP) {
        tcp_spec.hdr.src_port = htons(flow->sp);
        tcp_mask.hdr.src_port = 0xFFFF;
        tcp_spec.hdr.dst_port = htons(flow->dp);
        tcp_mask.hdr.dst_port = 0xFFFF;
        l4_spec = &tcp_spec;
        l4_mask = &tcp_mask;
        items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_TCP;
    } else {
        udp_spec.hdr.src_port = htons(flow->sp);
        udp_mask.hdr.src_port = 0xFFFF;
        udp_spec.hdr.dst_port = htons(flow->dp);
        udp_mask.hdr.dst_port = 0xFFFF;
        l4_spec = &udp_spec;
        l4_mask = &udp_mask;
        items[L4_INDEX].type = RTE_FLOW_ITEM_TYPE_UDP;
    }

    items[L3_INDEX].spec = ip_spec;
    items[L3_INDEX].mask = ip_mask;
    items[L4_INDEX].spec = l4_spec;
    items[L4_INDEX].mask = l4_mask;
	
    struct rte_flow_action_list_handle *action_list_handle = nfbDeviceRteFlowCreateIndirectAction(port_id, flow_handler_info);
	struct rte_flow_action_indirect_list indir_list = {
		.handle = action_list_handle,
		.conf = NULL,
	};
    action[0].conf = &indir_list;
    struct rte_flow *rule_handle = RteFlowCreateRuleAsync(dpdk_vars->port_id, rule_queue_id, bypass_resources->tbl, items, pattern_template_index, action, RTE_ACTIONS_TEMPLATE_DEFAULT, fc->bypass_data);
    
    if (rule_handle == NULL) {
            nfbDeviceRteFlowRuleDestroy(rule_queue_id, flow_handler_info);
            SC_ATOMIC_ADD(bypass_data->rte_bypass_flows_bypass_error, 1);
            SCReturnInt(0);
    }

    struct rte_flow_error flow_error = { 0 };
    int retval = rte_flow_push(port_id, p->dpdk_v.in_queue_id, &flow_error);
    if (retval != 0) {
        SCLogWarning("rte_flow bypass: worker push failed on queue %u: %s", p->dpdk_v.in_queue_id, flow_error.message);
    }

    int inet_family = FLOW_IS_IPV4(flow) ? AF_INET : AF_INET6;
    RteFlowSetFlowBypassInfo(fc, flow, rule_handle, NULL, action_list_handle, NULL, inet_family);
    flow_handler_info->in_queue_id = p->dpdk_v.in_queue_id;

    SC_ATOMIC_ADD(bypass_data->rte_bypass_rules_active, 2);
    SC_ATOMIC_ADD(bypass_data->rte_bypass_rules_created, 2);
    SC_ATOMIC_ADD(bypass_data->rte_bypass_rules_unchecked, 2);
    SC_ATOMIC_ADD(bypass_data->rte_bypass_flows_bypass_success, 1);

    SCReturnInt(1);
}

#pragma GCC diagnostic pop

#endif /* HAVE_DPDK */
/**
 * @}
 */
