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
 * \file
 *
 * \author Adam Kiripolsky <adamkiripolsky.official@gmail.com>
 */

#ifndef UTIL_DPDK_RSS
#define UTIL_DPDK_RSS

#include "suricata-common.h"

#ifdef HAVE_DPDK

#include "util-dpdk.h"

int DeviceSetRSSFlowQueues(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues);
int DeviceEnableSymHash(
        int port_id, const char *port_name, uint32_t ftype, enum rte_eth_hash_function function, int nb_rx_queues);
int DeviceSetSymHash(int port_id, const char *port_name, int enable);
int DeviceSetRSSFlowIPv4(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues);
int DeviceSetRSSFlowIPv4UDP(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues);
int DeviceSetRSSFlowIPv4TCP(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues);
int DeviceSetRSSFlowIPv4SCTP(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues);
int DeviceSetRSSFlowIPv4Frag(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues);
int DeviceSetRSSFlowIPv6(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues);
int DeviceSetRSSFlowIPv6UDP(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues);
int DeviceSetRSSFlowIPv6TCP(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues);
int DeviceSetRSSFlowIPv6SCTP(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues);
int DeviceSetRSSFlowIPv6Frag(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues);

#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_RSS */
