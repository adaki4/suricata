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
#define RTE_JUMP_GROUP 1

uint8_t RSS_HKEY[] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,                         // 40
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, // 52
};

/**
 * \brief Initialize RSS action configuration for
 *        RTE_FLOW RSS rule based on input arguments
 *
 * \param rss_conf RSS configuration
 * \param nb_rx_queues number of rx queues
 * \param queues array of queue indexes
 * \param func RSS hash function
 * \param set_key flag to set RSS hash key and its length
 * \return struct rte_flow_action_rss RSS action configuration
 *         to be used in a rule
 */
struct rte_flow_action_rss DPDKInitRSSAction(struct rte_eth_rss_conf rss_conf, int nb_rx_queues,
        uint16_t *queues, enum rte_eth_hash_function func, bool set_key)
{
    struct rte_flow_action_rss rss_action_conf = { 0 };
    rss_action_conf.func = func;
    rss_action_conf.level = 0;

    if (set_key) {
        rss_action_conf.key = rss_conf.rss_key;
        rss_action_conf.key_len = rss_conf.rss_key_len;
    } else {
        rss_action_conf.key = NULL;
        rss_action_conf.key_len = 0;
    }

    if (nb_rx_queues != 0) {
        for (int i = 0; i < nb_rx_queues; ++i)
            queues[i] = i;

        rss_action_conf.queue = queues;
    } else {
        rss_action_conf.queue = NULL;
    }
    rss_action_conf.queue_num = nb_rx_queues;

    return rss_action_conf;
}

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
/**
 * \brief Create an RSS rte_flow rule using the Template API.
 *
 * Creates pattern template, actions template, and template table,
 * then inserts the RSS rule via rte_flow_async_create + rte_flow_push.
 * Template handles are stored in rss_tmpl for later cleanup.
 *
 * \param port_id          The port identifier
 * \param port_name        The port name for logging
 * \param rss_conf         RSS action configuration
 * \param rss_type         RSS hash type
 * \param pattern          Pattern to match
 * \param nb_pattern_items Number of items in pattern (including END)
 * \param rss_tmpl         Output: template resources for cleanup
 * \return 0 on success, negative errno on failure
 */
int DPDKCreateRSSFlowTemplate(int port_id, const char *port_name,
        struct rte_flow_action_rss rss_conf, uint64_t rss_type,
        struct rte_flow_item *pattern, int nb_pattern_items,
        RteFlowRSSTemplateResources *rss_tmpl)
{
    struct rte_flow_error flow_error = { 0 };
    struct rte_flow_attr attr = {
        .ingress = 1,
        .priority = 1,
        .group = 0,
    };

    rss_conf.types = rss_type;

    /* Configure the port for Template API (may already be configured by bypass init) */
    struct rte_flow_port_attr port_attr = {
        .nb_conn_tracks = 0,
        .nb_counters = 0,
    };
    struct rte_flow_queue_attr queue_attr = { .size = 0 };
    const struct rte_flow_queue_attr *queue_attrs[] = { &queue_attr };
    int ret = rte_flow_configure(port_id, &port_attr, queue_attrs, 1, &flow_error);
    if (ret != 0 && ret != -EEXIST) {
        SCLogError("%s: rte_flow_configure failed: %s", port_name, flow_error.message);
        return ret;
    }

    /* --- Pattern Template --- */
    struct rte_flow_pattern_template_attr pt_attr = {
        .relaxed_matching = 0,
        .ingress = 1,
    };

    rss_tmpl->pt = rte_flow_pattern_template_create(
            port_id, &pt_attr, pattern, &flow_error);
    if (rss_tmpl->pt == NULL) {
        SCLogError("%s: RSS pattern template create error: %s",
                port_name, flow_error.message);
        return -1;
    }

    /* --- Actions Template --- */
    struct rte_flow_action actions[] = {
        [0] = { .type = RTE_FLOW_ACTION_TYPE_RSS, .conf = &rss_conf },
        [1] = { .type = RTE_FLOW_ACTION_TYPE_END },
    };

    struct rte_flow_actions_template_attr at_attr = {
        .ingress = 1,
    };

    /* --- Masks Template --- */
    struct rte_flow_action masks[] = {
        [0] = { .type = RTE_FLOW_ACTION_TYPE_RSS, .conf = &rss_conf },
        [1] = { .type = RTE_FLOW_ACTION_TYPE_END },
    };

    rss_tmpl->at = rte_flow_actions_template_create(
            port_id, &at_attr, actions, masks, &flow_error);
    if (rss_tmpl->at == NULL) {
        SCLogError("%s: RSS actions template create error: %s",
                port_name, flow_error.message);
        rte_flow_pattern_template_destroy(port_id, rss_tmpl->pt, &flow_error);
        rss_tmpl->pt = NULL;
        return -1;
    }

    /* --- Template Table --- */
    struct rte_flow_template_table_attr tbl_attr = {
        .flow_attr = attr,
        .nb_flows = 1,  /* RSS rules are singletons */
    };

    rss_tmpl->tbl = rte_flow_template_table_create(
            port_id, &tbl_attr, &rss_tmpl->pt, 1, &rss_tmpl->at, 1, &flow_error);
    if (rss_tmpl->tbl == NULL) {
        SCLogError("%s: RSS template table create error: %s",
                port_name, flow_error.message);
        rte_flow_actions_template_destroy(port_id, rss_tmpl->at, &flow_error);
        rte_flow_pattern_template_destroy(port_id, rss_tmpl->pt, &flow_error);
        rss_tmpl->at = NULL;
        rss_tmpl->pt = NULL;
        return -1;
    }

    /* --- Async Create --- */
    struct rte_flow_op_attr op_attr = { .postpone = 0 };
    struct rte_flow *flow = rte_flow_async_create(
            port_id, 0, &op_attr, rss_tmpl->tbl,
            pattern, 0, NULL, 0, NULL, &flow_error);
    if (flow == NULL) {
        SCLogError("%s: RSS async create error: %s", port_name, flow_error.message);
        rte_flow_template_table_destroy(port_id, rss_tmpl->tbl, &flow_error);
        rte_flow_actions_template_destroy(port_id, rss_tmpl->at, &flow_error);
        rte_flow_pattern_template_destroy(port_id, rss_tmpl->pt, &flow_error);
        memset(rss_tmpl, 0, sizeof(*rss_tmpl));
        return -1;
    }

    ret = rte_flow_push(port_id, 0, &flow_error);
    if (ret < 0) {
        SCLogError("%s: RSS push error: %s", port_name, flow_error.message);
        rte_flow_template_table_destroy(port_id, rss_tmpl->tbl, &flow_error);
        rte_flow_actions_template_destroy(port_id, rss_tmpl->at, &flow_error);
        rte_flow_pattern_template_destroy(port_id, rss_tmpl->pt, &flow_error);
        memset(rss_tmpl, 0, sizeof(*rss_tmpl));
        return -1;
    }

    rte_flow_pull(port_id, 0, NULL, 0, &flow_error);

    SCLogDebug("%s: RSS rte_flow rule created via Template API", port_name);
    return 0;
}
#endif /* RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0) */

/**
 * \brief Creates RTE_FLOW RSS rule used by NIC drivers
 *        to redistribute packets to different queues based
 *        on IP adresses.
 *
 * \param port_id The port identifier of the Ethernet device
 * \param port_name The port name of the Ethernet device
 * \param rss_conf RSS configuration
 * \return int 0 on success, a negative errno value otherwise
 */
int DPDKCreateRSSFlowGeneric(
        int port_id, const char *port_name, struct rte_flow_action_rss rss_conf)
{
    struct rte_flow_item pattern[] = { { 0 }, { 0 } };

    rss_conf.types = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_IPV6;
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
    RteFlowRSSTemplateResources rss_tmpl = { 0 };
    int ret = DPDKCreateRSSFlowTemplate(port_id, port_name, rss_conf,
            RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_IPV6, pattern, 2, &rss_tmpl);
    if (ret == 0) {
        /* Store template resources for cleanup — caller must provide storage */
        /* Note: For mlx5, the caller (mlx5DeviceSetRSS) should store rss_tmpl */
    }
    return ret;
#else
    /* Fallback: classic API */
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow_error flow_error = { 0 };

    attr.ingress = 1;
    attr.priority = 1;
    attr.group = RTE_JUMP_GROUP;

    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_conf;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow == NULL) {
        SCLogError("%s: rte_flow rule creation error: %s", port_name, flow_error.message);
        int ret = rte_flow_validate(port_id, &attr, pattern, action, &flow_error);
        SCLogError("%s: rte_flow rule validation error: %s, errmsg: %s", port_name,
                rte_strerror(-ret), flow_error.message);
        return ret;
    } else {
        SCLogDebug("%s: rte_flow rule created", port_name);
    }

    return 0;
#endif
}

/**
 * \brief Create RTE_FLOW RSS rule configured with pattern and rss_type
 *        but with no rx_queues configured. This is specific way of setting RTE_FLOW RSS rule
 *        for some drivers (mostly Intel NICs). This function's call must be preceded by
 *        call to function DeviceSetRSSFlowQueues().
 *
 * \param port_id The port identifier of the Ethernet device
 * \param port_name The port name of the Ethernet device
 * \param rss_conf RSS configuration
 * \param rss_type RSS hash type - only this type is used when creating hash with RSS hash function
 * \param pattern pattern to match incoming traffic
 * \return int 0 on success, a negative errno value otherwise
 */
int DPDKCreateRSSFlow(int port_id, const char *port_name, struct rte_flow_action_rss rss_conf,
        uint64_t rss_type, struct rte_flow_item *pattern)
{
    rss_conf.types = rss_type;

    /* Count pattern items */
    int nb_items = 0;
    while (pattern[nb_items].type != RTE_FLOW_ITEM_TYPE_END)
        nb_items++;
    nb_items++; /* include END */

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
    RteFlowRSSTemplateResources rss_tmpl = { 0 };
    int ret = DPDKCreateRSSFlowTemplate(port_id, port_name, rss_conf,
            rss_type, pattern, nb_items, &rss_tmpl);
    if (ret == 0) {
        /* Store template resources for cleanup — caller must provide storage */
        /* Note: For ice, the caller (iceDeviceSetRSS) should store rss_tmpl */
    }
    return ret;
#else
    /* Fallback: classic API */
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow_error flow_error = { 0 };

    attr.ingress = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_conf;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow == NULL) {
        SCLogError("%s: rte_flow rule creation error: %s", port_name, flow_error.message);
        int ret = rte_flow_validate(port_id, &attr, pattern, action, &flow_error);
        SCLogError("%s: rte_flow rule validation error: %s, errmsg: %s", port_name,
                rte_strerror(-ret), flow_error.message);
        return ret;
    } else {
        SCLogDebug("%s: rte_flow rule created", port_name);
    }

    return 0;
#endif
}

/**
 * \brief Some drivers (mostly Intel NICs) require specific way of setting RTE_FLOW RSS rules
 *        with one rule that sets up only queues and other rules that specify patterns to match with
 *        queues configured (created with function DeviceCreateRSSFlow() that should follow after
 *        this function's call).
 *
 * \param port_id The port identifier of the Ethernet device
 * \param port_name The port name of the Ethernet device
 * \param rss_conf RSS configuration
 * \return int 0 on success, a negative errno value otherwise
 */
int DPDKSetRSSFlowQueues(int port_id, const char *port_name, struct rte_flow_action_rss rss_conf)
{
    struct rte_flow_item pattern[] = { { 0 } };

    rss_conf.types = 0; // queues region can not be configured with types
    pattern[0].type = RTE_FLOW_ITEM_TYPE_END;

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
    RteFlowRSSTemplateResources rss_tmpl = { 0 };
    int ret = DPDKCreateRSSFlowTemplate(port_id, port_name, rss_conf,
            0, pattern, 1, &rss_tmpl);
    if (ret == 0) {
        /* Store template resources for cleanup — caller must provide storage */
    }
    return ret;
#else
    /* Fallback: classic API */
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow_error flow_error = { 0 };

    attr.ingress = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_conf;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow == NULL) {
        SCLogError("%s: rte_flow rule creation error: %s", port_name, flow_error.message);
        int ret = rte_flow_validate(port_id, &attr, pattern, action, &flow_error);
        SCLogError("%s: rte_flow rule validation error: %s, errmsg: %s", port_name,
                rte_strerror(-ret), flow_error.message);
        return ret;
    } else {
        SCLogDebug("%s: rte_flow rule created", port_name);
    }
    return 0;
#endif
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
