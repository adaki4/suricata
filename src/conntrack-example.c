#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_malloc.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <signal.h>

#include "main.h"

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		stop = 1;
	}
}

/* ============================================================================
 * Template Creation Helpers
 * ============================================================================ */

static struct rte_flow_pattern_template *
create_pattern_template(int port_id, struct rte_flow_item *pattern)
{
	struct rte_flow_pattern_template_attr attr = { .ingress = 1, };

	struct rte_flow_pattern_template *templ =
		rte_flow_pattern_template_create(port_id, &attr, pattern, &error);

	if (!templ)
		rte_exit(EXIT_FAILURE, "rte_flow_pattern_template_create() failed: %s\n", error.message);

	return templ;
}

static struct rte_flow_actions_template *
create_actions_template(int port_id, struct rte_flow_action *actions, struct rte_flow_action *masks)
{
	struct rte_flow_actions_template_attr attr = { .ingress = 1, };

	struct rte_flow_actions_template *templ =
		rte_flow_actions_template_create(port_id, &attr, actions, masks, &error);

	if (!templ)
		rte_exit(EXIT_FAILURE, "rte_flow_actions_template_create() failed: %s\n", error.message);

	return templ;
}

static struct rte_flow_template_table *
create_template_table(int port_id, uint32_t group, uint32_t nb_flows,
					  struct rte_flow_pattern_template **ptempls, uint32_t nb_ptempls,
					  struct rte_flow_actions_template **atempls, uint32_t nb_atempls)
{
	struct rte_flow_template_table_attr attr = {
		.flow_attr = {
			.group = group,
			.ingress = 1,
		},
		.nb_flows = nb_flows,
	};

	struct rte_flow_template_table *table = rte_flow_template_table_create(
		port_id, &attr, ptempls, nb_ptempls, atempls, nb_atempls, &error);

	if (!table)
		rte_exit(EXIT_FAILURE, "rte_flow_template_table_create() failed: %s\n", error.message);

	return table;
}

/* ============================================================================
 * Indirect Action Helpers
 * ============================================================================ */

static struct rte_flow_action_handle *
create_indirect_action(int port_id, uint32_t queue_id, struct rte_flow_action *action,
					   void *cookie)
{
	struct rte_flow_op_attr op_attr = { .postpone = 1 };
	struct rte_flow_indir_action_conf indir_conf = { .ingress = 1 };

	struct rte_flow_action_handle *handle = rte_flow_async_action_handle_create(
		port_id, queue_id, &op_attr, &indir_conf, action, cookie, &error);

	if (!handle)
		rte_exit(EXIT_FAILURE, "rte_flow_async_action_handle_create() failed: %s\n", error.message);

	app_flow_ctx.inflight++;
	return handle;
}

static void update_conntrack_direction(int port_id, uint32_t queue_id,
									 struct rte_flow_action_handle *handle,
									 void *cookie)
{
	struct rte_flow_op_attr op_attr = { .postpone = 1 };

	struct rte_flow_modify_conntrack update = {
		.new_ct = {
			.is_original_dir = 0,
		},
		.direction = 1,
	};

	int ret = rte_flow_async_action_handle_update(port_id, queue_id, &op_attr, handle, &update, cookie, &error);
	if (ret < 0)
		rte_exit(ret, "rte_flow_async_action_handle_update() failed: %d with: %s\n", ret, error.message);

	app_flow_ctx.inflight++;
}

static void query_action_handle(int port_id, struct rte_flow_action_handle *handle,
							   void *query_data,
							   uintptr_t cookie)
{
	struct rte_flow_op_attr op_attr = { .postpone = 1 };

	int ret = rte_flow_async_action_handle_query(port_id, FLOW_QUEUE_ID, &op_attr,
										 handle, query_data, (void *)cookie, &error);
	if (ret < 0)
		rte_exit(ret, "rte_flow_async_action_handle_query() failed: %d with: %s\n", ret, error.message);

	app_flow_ctx.inflight++;
}

/* ============================================================================
 * Rule Creation Helpers
 * ============================================================================ */

static struct rte_flow *
create_rule_async(int port_id, uint32_t queue_id, struct rte_flow_template_table *table,
				  struct rte_flow_item *pattern, struct rte_flow_action *actions,
				  void *cookie)
{
	struct rte_flow_op_attr op_attr = { .postpone = 1 };

	struct rte_flow *flow = rte_flow_async_create(
		port_id, queue_id, &op_attr, table,
		pattern, 0, actions, 0, cookie, &error);

	if (!flow)
		rte_exit(EXIT_FAILURE, "rte_flow_async_create() failed: %s\n", error.message);

	app_flow_ctx.inflight++;
	return flow;
}

/* ============================================================================
 * Flow Engine Setup
 * ============================================================================ */

static void flow_engine_configure(int port_id)
{
	struct rte_flow_port_info flow_port_info;
	struct rte_flow_queue_info flow_queue_info;

	int ret = rte_flow_info_get(port_id, &flow_port_info, &flow_queue_info, &error);
	if (ret < 0)
		rte_exit(ret, "rte_flow_info_get() failed: %d with: %s\n", ret, error.message);

	printf("rte_flow_port_info: max_queues: %u, max_conntracs: %u, supported_flags: %u\n"
		   "rte_flow_queue_info: max_size: %u\n",
		   flow_port_info.max_nb_queues, flow_port_info.max_nb_conn_tracks,
		   flow_port_info.supported_flags, flow_queue_info.max_size);

	struct rte_flow_port_attr flow_port_attr = {
		.host_port_id = port_id,
		.nb_conn_tracks = NB_CONNTRACS,
		.nb_counters = NB_COUNTERS,
	};

	struct rte_flow_queue_attr flow_queue_attr = {
		.size = FLOW_QUEUE_SIZE,
	};
	const struct rte_flow_queue_attr *flow_queue_attrs = &flow_queue_attr;

	ret = rte_flow_configure(port_id, &flow_port_attr, 1, &flow_queue_attrs, &error);
	if (ret < 0)
		rte_exit(ret, "rte_flow_configure() failed: %d with: %s\n", ret, error.message);
}

/* ============================================================================
 * Rule Template Setup
 * ============================================================================ */

static void setup_rule_templates_jump(int port_id)
{
	printf("Setting up jump rule templates (Group %d)...\n", GROUP_0);

	struct app_table_ctx *table = &app_flow_ctx.jump_table;

	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_IPV4 },
		{ .type = RTE_FLOW_ITEM_TYPE_TCP },
		{ .type = RTE_FLOW_ITEM_TYPE_END }
	};

	struct rte_flow_action actions[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_INDIRECT },
		{ .type = RTE_FLOW_ACTION_TYPE_JUMP },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};
	struct rte_flow_action actions_mask[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT },
		{ .type = RTE_FLOW_ACTION_TYPE_JUMP },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

	table->pattern_templ = create_pattern_template(port_id, pattern);
	table->actions_templ = create_actions_template(port_id, actions, actions_mask);
	table->group_id = GROUP_0;
	table->table = create_template_table(port_id, GROUP_0, 1, &table->pattern_templ, 1, &table->actions_templ, 1);
	table->used = true;
}

static void setup_rule_templates_ct(int port_id)
{
	printf("Setting up ct rule templates (Group %d)...\n", GROUP_3);

	struct app_table_ctx *table = &app_flow_ctx.ct_rule_table;

	struct rte_flow_item_ipv4 ipv4_spec = {0};
	struct rte_flow_item_ipv4 ipv4_mask = {
		.hdr = {
			.src_addr = 0xFFFFFFFF,
			.dst_addr = 0xFFFFFFFF,
		}
	};
	struct rte_flow_item_tcp tcp_spec = {0};
	struct rte_flow_item_tcp tcp_mask = {
		.hdr = {
			.src_port = 0xFFFF,
			.dst_port = 0xFFFF,
		}
	};

	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ipv4_spec, .mask = &ipv4_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_TCP, .spec = &tcp_spec, .mask = &tcp_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END }
	};

	struct rte_flow_action actions[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_INDIRECT },
		{ .type = RTE_FLOW_ACTION_TYPE_JUMP },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};
	struct rte_flow_action actions_mask[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_CONNTRACK },
		{ .type = RTE_FLOW_ACTION_TYPE_JUMP },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

	table->pattern_templ = create_pattern_template(port_id, pattern);
	table->actions_templ = create_actions_template(port_id, actions, actions_mask);
	table->group_id = GROUP_3;
	table->table = create_template_table(port_id, GROUP_3, 2,
								  &table->pattern_templ, 1,
								  &table->actions_templ, 1);
	table->used = true;
}

static void setup_rule_templates_match(int port_id)
{
	printf("Setting up match rule templates (Group %d)...\n", GROUP_5);

	struct app_table_ctx *table = &app_flow_ctx.ct_match_table;

	struct rte_flow_item_ipv4 ipv4_spec = {
		.hdr = {
			.src_addr = 0,
			.dst_addr = 0,
		}
	};
	struct rte_flow_item_ipv4 ipv4_mask = {
		.hdr = {
			.src_addr = 0xFFFFFFFF,
			.dst_addr = 0xFFFFFFFF,
		}
	};
	struct rte_flow_item_tcp tcp_spec = {0};
	struct rte_flow_item_tcp tcp_mask = {
		.hdr = {
			.src_port = 0xFFFF,
			.dst_port = 0xFFFF,
		}
	};
	struct rte_flow_item_conntrack ct_spec = {0};
	struct rte_flow_item_conntrack ct_mask = {
		.flags = RTE_FLOW_CONNTRACK_PKT_STATE_VALID 	|
				 RTE_FLOW_CONNTRACK_PKT_STATE_CHANGED 	|
				 RTE_FLOW_CONNTRACK_PKT_STATE_INVALID 	|
				 RTE_FLOW_CONNTRACK_PKT_STATE_DISABLED 	|
				 RTE_FLOW_CONNTRACK_PKT_STATE_BAD,
	};

	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ipv4_spec, .mask = &ipv4_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_TCP, .spec = &tcp_spec, .mask = &tcp_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_CONNTRACK, .spec = &ct_spec, .mask = &ct_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END }
	};

	struct rte_flow_action actions[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_INDIRECT },
		{ .type = RTE_FLOW_ACTION_TYPE_DROP },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};
	struct rte_flow_action actions_mask[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT },
		{ .type = RTE_FLOW_ACTION_TYPE_DROP },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

	table->pattern_templ = create_pattern_template(port_id, pattern);
	table->actions_templ = create_actions_template(port_id, actions, actions_mask);
	table->group_id = GROUP_5;
	table->table = create_template_table(port_id, GROUP_5, 10,
			  &table->pattern_templ, 1,
			  &table->actions_templ, 1);
	table->used = true;
}

/* ============================================================================
 * Rule Creation
 * ============================================================================ */

static void create_rule_jump(int port_id)
{
	printf("Creating jump rule Group %d)...\n", GROUP_0);

	struct app_table_ctx *table = &app_flow_ctx.jump_table;
	struct app_rule_ctx *rule = &table->rules[0];

	struct rte_flow_action_count count_conf = {0};
	struct rte_flow_action count_action = {
		.type = RTE_FLOW_ACTION_TYPE_COUNT,
		.conf = &count_conf
	};

	rule->indirect_handle = create_indirect_action(port_id, FLOW_QUEUE_ID, &count_action,
								  (void *)(uintptr_t)(COOKIE_BASE + app_flow_ctx.inflight));
	rule->used = true;

	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_IPV4 },
		{ .type = RTE_FLOW_ITEM_TYPE_TCP },
		{ .type = RTE_FLOW_ITEM_TYPE_END }
	};

	struct rte_flow_action_jump jump_conf = { .group = GROUP_3 };
	struct rte_flow_action actions[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_INDIRECT, .conf = rule->indirect_handle },
		{ .type = RTE_FLOW_ACTION_TYPE_JUMP, .conf = &jump_conf },
		{ .type = RTE_FLOW_ACTION_TYPE_END }
	};

	rule->cookie = (void *)(uintptr_t)(COOKIE_BASE + app_flow_ctx.inflight);
	rule->flow = create_rule_async(port_id, FLOW_QUEUE_ID, table->table,
								   pattern, actions, rule->cookie);
	table->nb_rules++;
}

static void create_rules_ct_match(int port_id, uint32_t queue_id,
                                   uint32_t src_ip, uint32_t dst_ip,
                                   uint16_t src_port, uint16_t dst_port)
{
	/*  Follow the Mellanox documentation: 
	https://docs.nvidia.com/networking/display/mlnxdpdk2211231051lts/connection+tracking+window+validation

	To offload a connection, you must use the API as follows:
     1. Create a SW CT context that matches the connection parameters. 
	 	It is important to set .is_original_port= 1.
     2. Create a CT action that points to the SW context, 
	 	and then commit it using rte_flow_action_handle_createwhich will return an action_handle.
     3. Insert the rule(*) that matches on the 5-tuple of the connection. 
	 	However, instead of using action CT, you can use the action_handle created and insert that.
     4. Modify the CT action that was created in 2, such that .is_original_port= 0. 
	 	You can modify the action by using rte_flow_action_handle_updateand providing the struct rte_flow_modify_conntrack parameter.
     5. Insert the rule(**) that matches on the reverse 5-tuple of the connection. Same as 3.
	*/

	struct app_table_ctx *ct_table = &app_flow_ctx.ct_rule_table;
	struct app_table_ctx *match_table = &app_flow_ctx.ct_match_table;

	uint32_t rule_idx = ct_table->nb_rules;
	if (rule_idx + 2 > APP_MAX_RULES_PER_TABLE) {
		printf("Warning: CT rule table full, cannot offload flow\n");
		return;
	}

	struct app_rule_ctx *rule_orig = &ct_table->rules[rule_idx];
	struct app_rule_ctx *rule_reply = &ct_table->rules[rule_idx + 1];

	printf("Creating CT rules for flow %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
		(src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
		(src_ip >> 8) & 0xFF, (src_ip >> 0) & 0xFF,
		src_port,
		(dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,
		(dst_ip >> 8) & 0xFF, (dst_ip >> 0) & 0xFF,
		dst_port);

	// Pattern masks for IP/TCP
	struct rte_flow_item_ipv4 ipv4_mask = {
		.hdr = {
			.src_addr = 0xFFFFFFFF,
			.dst_addr = 0xFFFFFFFF,
		}
	};
	struct rte_flow_item_tcp tcp_mask = {
		.hdr = {
			.src_port = 0xFFFF,
			.dst_port = 0xFFFF,
		}
	};

	// Pattern for original direction
	struct rte_flow_item_ipv4 ipv4_orig = {
		.hdr = {
			.src_addr = rte_cpu_to_be_32(src_ip),
			.dst_addr = rte_cpu_to_be_32(dst_ip),
		}
	};
	struct rte_flow_item_tcp tcp_orig = {
		.hdr = {
			.src_port = rte_cpu_to_be_16(src_port),
			.dst_port = rte_cpu_to_be_16(dst_port),
		}
	};

	struct rte_flow_item pattern_orig[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ipv4_orig, .mask = &ipv4_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_TCP, .spec = &tcp_orig, .mask = &tcp_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END }
	};

	// Pattern for reply direction
	struct rte_flow_item_ipv4 ipv4_reply = {
		.hdr = {
			.src_addr = rte_cpu_to_be_32(dst_ip),
			.dst_addr = rte_cpu_to_be_32(src_ip),
		}
	};
	struct rte_flow_item_tcp tcp_reply = {
		.hdr = {
			.src_port = rte_cpu_to_be_16(dst_port),
			.dst_port = rte_cpu_to_be_16(src_port),
		}
	};

	struct rte_flow_item pattern_reply[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ipv4_reply, .mask = &ipv4_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_TCP, .spec = &tcp_reply, .mask = &tcp_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END }
	};

	struct rte_flow_action_jump jump_conf = { .group = GROUP_5 };

	// The conntrack conf struct
	struct rte_flow_action_conntrack conntrack_conf = {
		.peer_port = PORT_ID,
		.is_original_dir = 1,
		.enable = 1,
		.live_connection = 1,
		.selective_ack = 0,
		.challenge_ack_passed = 0,
		.last_direction = 0,
		.liberal_mode = 0,
		.state = 1,
		.max_ack_window = 0,
		.retransmission_limit = 0,
		.original_dir = {
			.scale = 0,
			.close_initiated = 0,
			.last_ack_seen = 0,
			.data_unacked = 0,
			.sent_end = 0,
			.reply_end = 0,
			.max_win = 0,
			.max_ack = 0,
		},
		.reply_dir = {
			.scale = 0,
			.close_initiated = 0,
			.last_ack_seen = 0,
			.data_unacked = 0,
			.sent_end = 0,
			.reply_end = 0,
			.max_win = 0,
			.max_ack = 0,
		},
		.last_window = 0,
		.last_index = 0,
		.last_seq = 0,
		.last_ack = 0,
		.last_end = 0,
	};
	struct rte_flow_action conntrack_action = {
		.type = RTE_FLOW_ACTION_TYPE_CONNTRACK,
		.conf = &conntrack_conf
	};

	// STEP 1: Create CONNTRACK indirect action handle
	struct rte_flow_action_handle *conntrack_handle = create_indirect_action(port_id, queue_id, &conntrack_action,
																		 (void *)(uintptr_t)(COOKIE_BASE + app_flow_ctx.inflight));

	// Conntrack handle is stored in the orig rule
	rule_orig->indirect_handle = conntrack_handle;

	struct rte_flow_action conntrack_act_indirect = {
		.type = RTE_FLOW_ACTION_TYPE_INDIRECT,
		.conf = conntrack_handle
	};
	struct rte_flow_action actions_ct[] = {
		conntrack_act_indirect,
		{ .type = RTE_FLOW_ACTION_TYPE_JUMP, .conf = &jump_conf },
		{ .type = RTE_FLOW_ACTION_TYPE_END }
	};

	// STEP 2: Create original direction rule (Group 3)
	rule_orig->cookie = (void *)(uintptr_t)(COOKIE_BASE + app_flow_ctx.inflight);
	rule_orig->flow = create_rule_async(port_id, queue_id, ct_table->table,
									  pattern_orig, actions_ct, rule_orig->cookie);
	rule_orig->used = true;

	// STEP 3: Update conntrack handle to is_original_dir = 0 for reply direction
	update_conntrack_direction(port_id, queue_id, conntrack_handle,
							   (void *)(uintptr_t)(COOKIE_BASE + app_flow_ctx.inflight));

	// STEP 4: Create reply direction rule with updated handle (Group 3)
	rule_reply->cookie = (void *)(uintptr_t)(COOKIE_BASE + app_flow_ctx.inflight);
	rule_reply->flow = create_rule_async(port_id, queue_id, ct_table->table,
									  pattern_reply, actions_ct, rule_reply->cookie);
	rule_reply->used = true;
	// Reply rule shares the same conntrack handle - no separate handle stored

	ct_table->nb_rules += 2;

	// STEP 5: Create match rules for CT states (Group 5)
	uint32_t match_rule_idx = match_table->nb_rules;
	if (match_rule_idx + CT_TOTAL_MATCHING_RULES > APP_MAX_RULES_PER_TABLE) {
		printf("Warning: Match rule table full, cannot create state rules\n");
		return;
	}

	// CT state specs for all 5 states
	struct rte_flow_item_conntrack ct_specs[5] = {
		{ .flags = RTE_FLOW_CONNTRACK_PKT_STATE_VALID },
		{ .flags = RTE_FLOW_CONNTRACK_PKT_STATE_CHANGED },
		{ .flags = RTE_FLOW_CONNTRACK_PKT_STATE_INVALID },
		{ .flags = RTE_FLOW_CONNTRACK_PKT_STATE_DISABLED },
		{ .flags = RTE_FLOW_CONNTRACK_PKT_STATE_BAD },
	};
	const char *ct_state_names[5] = { "valid", "changed", "invalid", "disabled", "bad" };

	// Create 10 rules: 5 CT states x 2 directions (orig, reply)
	int mr_idx = 0;
	for (int dir = 0; dir < 2; dir++) {
		const char *dir_name = (dir == 0) ? "orig" : "reply";
		struct rte_flow_item_ipv4 *ipv4_spec = (dir == 0) ? &ipv4_orig : &ipv4_reply;
		struct rte_flow_item_tcp *tcp_spec = (dir == 0) ? &tcp_orig : &tcp_reply;

		for (int state = 0; state < 5; state++) {
			struct app_rule_ctx *rule = &match_table->rules[match_rule_idx + mr_idx];

			// Create count action for this rule
			struct rte_flow_action_count mcount_conf = {0};
			struct rte_flow_action mcount_action = {
				.type = RTE_FLOW_ACTION_TYPE_COUNT,
				.conf = &mcount_conf
			};

			rule->indirect_handle = create_indirect_action(port_id, queue_id, &mcount_action,
									  (void *)(uintptr_t)(COOKIE_BASE + app_flow_ctx.inflight));

			// Build pattern with CT state match
			struct rte_flow_item pattern[] = {
				{ .type = RTE_FLOW_ITEM_TYPE_ETH },
				{ .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = ipv4_spec, .mask = &ipv4_mask },
				{ .type = RTE_FLOW_ITEM_TYPE_TCP, .spec = tcp_spec, .mask = &tcp_mask },
				{ .type = RTE_FLOW_ITEM_TYPE_CONNTRACK, .spec = &ct_specs[state], .mask = NULL },
				{ .type = RTE_FLOW_ITEM_TYPE_END }
			};

			// Build actions: count + drop
			struct rte_flow_action actions[] = {
				{ .type = RTE_FLOW_ACTION_TYPE_INDIRECT, .conf = rule->indirect_handle },
				{ .type = RTE_FLOW_ACTION_TYPE_DROP },
				{ .type = RTE_FLOW_ACTION_TYPE_END }
			};

			rule->cookie = (void *)(uintptr_t)(COOKIE_BASE + app_flow_ctx.inflight);
			rule->flow = create_rule_async(port_id, queue_id, match_table->table,
						       pattern, actions, rule->cookie);
			rule->used = true;

			printf("  Created %s_%s match rule\n", dir_name, ct_state_names[state]);
			mr_idx++;
		}
	}

	match_table->nb_rules += CT_TOTAL_MATCHING_RULES;

	printf("Offloaded flow with %d CT rules and %d match rules\n",
		   2, CT_TOTAL_MATCHING_RULES);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char *argv[])
{
	int ret;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(ret, "rte_eal_init() failed: %d\n", ret);

	setup_port(PORT_ID, NB_RX_QUEUES, HWRING_SIZE);
	
	// Configure the flow engine
	flow_engine_configure(PORT_ID);

	// Setup flow templates Group 0: JMP G3 -> Group 3: CONNTRACK, JMP G5 -> Group 5: Match on CONNTRACK_STATE, CNT, QUEUE
	setup_rule_templates_jump(PORT_ID);
	setup_rule_templates_ct(PORT_ID);
	setup_rule_templates_match(PORT_ID);

	ret = rte_eth_dev_start(PORT_ID);
	if (ret < 0)
		rte_exit(ret, "rte_eth_dev_start() failed: %d\n", ret);

	// Create flow rules
	create_rule_jump(PORT_ID);
	// Flow: 10.0.0.1:12345 -> 10.0.0.2:80 (matches flow.py test packets)
	create_rules_ct_match(PORT_ID, FLOW_QUEUE_ID,
						   RTE_IPV4(10, 0, 0, 1),
						   RTE_IPV4(10, 0, 0, 2),
						   12345, 80);

	// Push the created flows and pull results
	ret = rte_flow_push(PORT_ID, FLOW_QUEUE_ID, &error);
	if (ret < 0)
		rte_exit(ret, "rte_flow_push() failed: %d with: %s\n", ret, error.message);
	
	rte_delay_ms(500);
	printf("Pulling async rule results (%lu inflight)...\n", app_flow_ctx.inflight);
	ret = rte_flow_pull(PORT_ID, FLOW_QUEUE_ID, app_flow_ctx.results, app_flow_ctx.inflight, &error);
	if (ret < 0) {
		rte_exit(ret, "rte_flow_pull() failed: %d with: %s\n", ret, error.message);
	} else if (ret > 0) {
		printf("Got %d results\n", ret);
		for (int i = 0; i < ret; ++i) {
			printf("  Result %d: cookie=%p, status=%d (0=success)\n",
					i, app_flow_ctx.results[i].user_data, app_flow_ctx.results[i].status);
			app_flow_ctx.inflight--;
		}
	}
	if (app_flow_ctx.inflight > 0)
		rte_exit(ret, "%lu operations still inflight after pull\n", app_flow_ctx.inflight);


	// The rules are succesfully loaded now query the conntrack and counters in loop

	// Query the indirect action handles
	struct rte_flow_query_count query_data_count1 = {0};
	struct rte_flow_query_count ct_match_counts[CT_TOTAL_MATCHING_RULES] = {{0}};
	struct rte_flow_action_conntrack ct_query_data = {0};
	const char *ct_match_names[CT_TOTAL_MATCHING_RULES] = {
		"orig-valid", "orig-changed", "orig-invalid", "orig-disabled", "orig-bad",
		"reply-valid", "reply-changed", "reply-invalid", "reply-disabled", "reply-bad"
	};

	while (!stop) {
		rte_delay_ms(500);

		// Query the jump counter
		query_action_handle(PORT_ID, app_flow_ctx.jump_table.rules[0].indirect_handle,
						   &query_data_count1, QUERY_COOKIE_COUNT1);

		// Query CT match rule counters
		for (unsigned i = 0; i < CT_TOTAL_MATCHING_RULES; i++) {
			if (i < app_flow_ctx.ct_match_table.nb_rules) {
				struct app_rule_ctx *rule = &app_flow_ctx.ct_match_table.rules[i];
				if (rule->used && rule->indirect_handle) {
					query_action_handle(PORT_ID, rule->indirect_handle,
									   &ct_match_counts[i], QUERY_COOKIE_COUNT3 + i);
				}
			}
		}
		// Query conntrack handle from first CT rule
		for (uint32_t tbl = 0; tbl < app_flow_ctx.ct_rule_table.nb_rules; tbl++) {
			struct app_rule_ctx *rule = &app_flow_ctx.ct_rule_table.rules[tbl];
			if (rule->used && rule->indirect_handle) {
				query_action_handle(PORT_ID, rule->indirect_handle,
								   &ct_query_data, QUERY_COOKIE_CONNTRACK + tbl);

				break;
			}
		}

		// Push the queries
		ret = rte_flow_push(PORT_ID, FLOW_QUEUE_ID, &error);
		if (ret < 0)
			rte_exit(ret, "rte_flow_push() failed: %d with: %s\n", ret, error.message);

		rte_delay_ms(500);

		// Pull the results
		ret = rte_flow_pull(PORT_ID, FLOW_QUEUE_ID, app_flow_ctx.results, app_flow_ctx.inflight, &error);
		if (ret < 0)
			rte_exit(ret, "rte_flow_pull() failed: %d with: %s\n", ret, error.message);

		// Print the results
		if (ret > 0) {
			for (int i = 0; i < ret; ++i) {
				uintptr_t cookie = (uintptr_t)app_flow_ctx.results[i].user_data;
				if (cookie == QUERY_COOKIE_COUNT1) {
					print_count_results("Jump Rule Count", &query_data_count1);
				} else if (cookie >= QUERY_COOKIE_COUNT3 && cookie < QUERY_COOKIE_COUNT3 + CT_TOTAL_MATCHING_RULES) {
					int idx = cookie - QUERY_COOKIE_COUNT3;
					print_count_results(ct_match_names[idx], &ct_match_counts[idx]);
				} else if (cookie >= QUERY_COOKIE_CONNTRACK && cookie < QUERY_COOKIE_CONNTRACK + APP_MAX_RULES_PER_TABLE) {
					print_conntrack_results(&ct_query_data);
				}
				app_flow_ctx.inflight--;
			}
			fflush(stdout);
		}
	}

	printf("\nShutting down...\n");
	cleanup_all_rules(PORT_ID, FLOW_QUEUE_ID);
	cleanup_all_tables(PORT_ID);
	teardown_port(PORT_ID);

	return 0;
}
