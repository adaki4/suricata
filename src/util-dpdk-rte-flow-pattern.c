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
 * \author Adam Kiripolsky <adam.kiripolsky@cesnet.cz>
 *
 * DPDK rte_flow rules util functions
 *
 */

#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-rte-flow.h"
#include "util-dpdk-rte-flow-pattern.h"
#include "runmode-dpdk.h"
#include "rte_flow.h"

#ifdef HAVE_DPDK

enum index {
    /* Special tokens. */
	ZERO = 0,
	END,
	START_SET,
	END_SET,

	/* Create tokens */
	FLOW,
	VC_INGRESS,
	CREATE,

	/* Action tokens */
	ACTIONS,
	ACTION_NEXT,
	ACTION_END,
	//ACTION_QUEUE,
	ACTION_DROP,
	//ACTION_COUNT,
	//ACTION_NEXT,


    /* Common tokens. */
	COMMON_INTEGER,
	COMMON_UNSIGNED,
	COMMON_PREFIX,
	COMMON_BOOLEAN,
	COMMON_STRING,
	COMMON_HEX,
	COMMON_FILE_PATH,
	COMMON_MAC_ADDR,
	COMMON_IPV4_ADDR,
	COMMON_IPV6_ADDR,
	COMMON_RULE_ID,
	COMMON_PORT_ID,
	COMMON_GROUP_ID,
	COMMON_PRIORITY_LEVEL,
	COMMON_INDIRECT_ACTION_ID,
	COMMON_PROFILE_ID,
	COMMON_POLICY_ID,
	COMMON_FLEX_HANDLE,
	COMMON_FLEX_TOKEN,
	COMMON_PATTERN_TEMPLATE_ID,
	COMMON_ACTIONS_TEMPLATE_ID,
	COMMON_TABLE_ID,
	COMMON_QUEUE_ID,

	/* Validate/create pattern. */
	ITEM_PATTERN,
	ITEM_PARAM_IS,
	ITEM_PARAM_SPEC,
	ITEM_PARAM_LAST,
	ITEM_PARAM_MASK,
	ITEM_NEXT,
	ITEM_END,
	ITEM_VOID,
	ITEM_ANY,
	ITEM_PORT_ID,
	//ITEM_RAW,
	ITEM_ETH,
    //ITEM_RAW_SIZE,
	ITEM_VLAN,
	ITEM_IPV4,
	ITEM_IPV4_SRC,
	ITEM_IPV4_DST,
	ITEM_IPV6,
	ITEM_IPV6_SRC,
	ITEM_IPV6_DST,
	ITEM_ICMP,
    ITEM_ICMP6,
	ITEM_UDP,
	ITEM_UDP_SRC,
	ITEM_UDP_DST,
	ITEM_TCP,
	ITEM_TCP_SRC,
	ITEM_TCP_DST,
	ITEM_SCTP,
	ITEM_SCTP_SRC,
	ITEM_SCTP_DST,
	ITEM_VXLAN,
	ITEM_E_TAG,
	ITEM_NVGRE,
	ITEM_MPLS,
	ITEM_GRE,
	ITEM_FUZZY,
	ITEM_GTP,
	ITEM_GTPC,
	ITEM_GTPU,
	ITEM_GENEVE,
	ITEM_VXLAN_GPE,
};

static const enum index item_param[] = {
	ITEM_PARAM_IS,
	ITEM_PARAM_SPEC,
	ITEM_PARAM_LAST,
	ITEM_PARAM_MASK,
	ZERO,
};

static const enum index next_item[] = {
	ITEM_END,
	ITEM_VOID,
	ITEM_ANY,
	ITEM_PORT_ID,
	//ITEM_RAW,
    //ITEM_RAW_SIZE,
	ITEM_ETH,
	ITEM_VLAN,
	ITEM_IPV4,
	ITEM_IPV6,
	ITEM_ICMP,
	ITEM_UDP,
	ITEM_TCP,
	ITEM_SCTP,
	ITEM_VXLAN,
	ITEM_E_TAG,
	ITEM_NVGRE,
	ITEM_MPLS,
	ITEM_GRE,
	ITEM_FUZZY,
	ITEM_GTP,
	ITEM_GTPC,
	ITEM_GTPU,
	ITEM_GENEVE,
	ITEM_VXLAN_GPE,
	ITEM_ICMP6,
	END_SET,
	ZERO,
};

static const enum index item_ipv4[] = {
	ITEM_IPV4_SRC,
	ITEM_IPV4_DST,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_ipv6[] = {
	ITEM_IPV6_SRC,
	ITEM_IPV6_DST,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_ipv6_routing_ext[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_icmp[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_vlan[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_udp[] = {
	ITEM_UDP_SRC,
	ITEM_UDP_DST,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_tcp[] = {
	ITEM_TCP_SRC,
	ITEM_TCP_DST,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_sctp[] = {
	ITEM_SCTP_SRC,
	ITEM_SCTP_DST,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_vxlan_gpe[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index next_vc_attr[] = {
	VC_INGRESS,
	ITEM_PATTERN,
	ZERO,
};

static const enum index item_any[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_port_id[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_eth[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_vxlan[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_e_tag[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_mpls[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_nvgre[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_gre[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_gtp[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_fuzzy[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_gtpu[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_gtpc[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_geneve[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_icmp6[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index next_action[] = {
	ACTION_END,
	ACTION_DROP,
	ZERO,
};


/** Maximum number of subsequent tokens and arguments on the stack. */
#define CTX_STACK_SIZE 16

/** Static initializer for the args field. */
#define ARGS(...) (const struct arg *const []){ __VA_ARGS__, NULL, }

/** Same as ARGS_ENTRY() using network byte ordering. */
#define ARGS_ENTRY_HTON(s, f) \
	(&(const struct arg){ \
		.hton = 1, \
		.offset = offsetof(s, f), \
		.size = sizeof(((s *)0)->f), \
	})

/** Same as ARGS_ENTRY_HTON() for a single argument, without structure. */
#define ARG_ENTRY_HTON(s) \
	(&(const struct arg){ \
		.hton = 1, \
		.offset = 0, \
		.size = sizeof(s), \
	})

#define PRIV_ITEM(t, s) \
	(&(const struct parse_item_priv){ \
		.type = RTE_FLOW_ITEM_TYPE_ ## t, \
		.size = s, \
	})

/** Private data for actions. */
struct parse_action_priv {
	enum rte_flow_action_type type; /**< Action type. */
	uint32_t size; /**< Size of action configuration structure. */
};

#define PRIV_ACTION(t, s) \
	(&(const struct parse_action_priv){ \
		.type = RTE_FLOW_ACTION_TYPE_ ## t, \
		.size = s, \
	})

/** Static initializer for the args field. */
#define ARGS(...) (const struct arg *const []){ __VA_ARGS__, NULL, }

/** Static initializer for ARGS() to target a field. */
#define ARGS_ENTRY(s, f) \
	(&(const struct arg){ \
		.offset = offsetof(s, f), \
		.size = sizeof(((s *)0)->f), \
	})

/** Static initializer for the next field. */
#define NEXT(...) (const enum index *const []){ __VA_ARGS__, NULL, }

/** Static initializer for a NEXT() entry. */
#define NEXT_ENTRY(...) (const enum index []){ __VA_ARGS__, ZERO, }

/** Token argument. */
struct arg {
	uint32_t hton:1; /**< Use network byte ordering. */
	uint32_t sign:1; /**< Value is signed. */
	uint32_t bounded:1; /**< Value is bounded. */
	uintmax_t min; /**< Minimum value if bounded. */
	uintmax_t max; /**< Maximum value if bounded. */
	uint32_t offset; /**< Relative offset from ctx->object. */
	uint32_t size; /**< Field size. */
	const uint8_t *mask; /**< Bit-mask to use instead of offset/size. */
};

enum rte_flow_query_update_mode {
	RTE_FLOW_QU_QUERY_FIRST = 1,  /**< Query before update. */
	RTE_FLOW_QU_UPDATE_FIRST,     /**< Query after  update. */
};

struct tunnel_ops {
	uint32_t id;
	char type[16];
	uint32_t enabled:1;
	uint32_t actions:1;
	uint32_t items:1;
};

enum rte_flow_encap_hash_field {
	/** Calculate hash placed in UDP source port field. */
	RTE_FLOW_ENCAP_HASH_FIELD_SRC_PORT,
	/** Calculate hash placed in NVGRE flow ID field. */
	RTE_FLOW_ENCAP_HASH_FIELD_NVGRE_FLOW_ID,
};


struct buffer {
	enum index command; /**< Flow command. */
	uint16_t port; /**< Affected port ID. */
	uint16_t queue; /** Async queue ID. */
	bool postpone; /** Postpone async operation */
	union {
		struct {
			struct rte_flow_port_attr port_attr;
			uint32_t nb_queue;
			struct rte_flow_queue_attr queue_attr;
		} configure; /**< Configuration arguments. */
		struct {
			uint32_t *template_id;
			uint32_t template_id_n;
		} templ_destroy; /**< Template destroy arguments. */
		struct {
			uint32_t id;
			struct rte_flow_template_table_attr attr;
			uint32_t *pat_templ_id;
			uint32_t pat_templ_id_n;
			uint32_t *act_templ_id;
			uint32_t act_templ_id_n;
		} table; /**< Table arguments. */
		struct {
			uint32_t *table_id;
			uint32_t table_id_n;
		} table_destroy; /**< Template destroy arguments. */
		struct {
			uint32_t *action_id;
			uint32_t action_id_n;
		} ia_destroy; /**< Indirect action destroy arguments. */
		struct {
			uint32_t action_id;
			enum rte_flow_query_update_mode qu_mode;
		} ia; /* Indirect action query arguments */
		struct {
			uint32_t table_id;
			uint32_t pat_templ_id;
			uint32_t rule_id;
			uint32_t act_templ_id;
			struct rte_flow_attr attr;
			struct tunnel_ops tunnel_ops;
			uintptr_t user_id;
			struct rte_flow_item *pattern;
			struct rte_flow_action *actions;
			struct rte_flow_action *masks;
			uint32_t pattern_n;
			uint32_t actions_n;
			uint8_t *data;
			enum rte_flow_encap_hash_field field;
			uint8_t encap_hash;
		} vc; /**< Validate/create arguments. */
		struct {
			uint64_t *rule;
			uint64_t rule_n;
			bool is_user_id;
		} destroy; /**< Destroy arguments. */
		struct {
			char file[128];
			bool mode;
			uint64_t rule;
			bool is_user_id;
		} dump; /**< Dump arguments. */
		struct {
			uint64_t rule;
			struct rte_flow_action action;
			bool is_user_id;
		} query; /**< Query arguments. */
		struct {
			uint32_t *group;
			uint32_t group_n;
		} list; /**< List arguments. */
		struct {
			int set;
		} isolate; /**< Isolated mode arguments. */
		struct {
			int destroy;
		} aged; /**< Aged arguments. */
		struct {
			uint32_t policy_id;
		} policy;/**< Policy arguments. */
		struct {
			uint16_t token;
			uintptr_t uintptr;
			char filename[128];
		} flex; /**< Flex arguments*/
	} args; /**< Command arguments. */
};


/** Parser context. */
struct context {
	/** Stack of subsequent token lists to process. */
	const enum index *next[CTX_STACK_SIZE];
	/** Arguments for stacked tokens. */
	const void *args[CTX_STACK_SIZE];
	enum index curr; /**< Current token index. */
	enum index prev; /**< Index of the last token seen. */
	int next_num; /**< Number of entries in next[]. */
	int args_num; /**< Number of entries in args[]. */
	uint32_t eol:1; /**< EOL has been detected. */
	uint32_t last:1; /**< No more arguments. */
	uint16_t port; /**< Current port ID (for completions). */
	uint32_t objdata; /**< Object-specific data. */
	void *object; /**< Address of current object for relative offsets. */
	void *objmask; /**< Object a full mask must be written to. */
};


static struct context cmd_flow_context;

/** Initialize context. */
static void
cmd_flow_context_init(struct context *ctx)
{
	/* A full memset() is not necessary. */
	ctx->curr = ZERO;
	ctx->prev = ZERO;
	ctx->next_num = 0;
	ctx->args_num = 0;
	ctx->eol = 0;
	ctx->last = 0;
	ctx->objdata = 0;
	ctx->object = NULL;
	ctx->objmask = NULL;
}

struct token {
	/** Type displayed during completion (defaults to "TOKEN"). */
	const char *type;
	/** Private data used by parser functions. */
	const void *priv;
	/**
	 * Lists of subsequent tokens to push on the stack. Each call to the
	 * parser consumes the last entry of that stack.
	 */
	const enum index *const *next;
	/** Arguments stack for subsequent tokens that need them. */
	const struct arg *const *args;
	/**
	 * Token-processing callback, returns -1 in case of error, the
	 * length of the matched string otherwise. If NULL, attempts to
	 * match the token name.
	 *
	 * If buf is not NULL, the result should be stored in it according
	 * to context. An error is returned if not large enough.
	 */
	int (*call)(struct context *ctx, const struct token *token,
		    const char *str, unsigned int len,
		    void *buf, unsigned int size);
	/** Mandatory token name, no default value. */
	const char *name;
};

struct parse_item_priv {
	enum rte_flow_item_type type; /**< Item type. */
	uint32_t size; /**< Size of item specification structure. */
};

static int parse_vc(struct context *, const struct token *,
		    const char *, unsigned int,
		    void *, unsigned int);
static int parse_vc_spec(struct context *, const struct token *,
			 const char *, unsigned int, void *, unsigned int);
static int parse_init(struct context *, const struct token *,
		      const char *, unsigned int,
		      void *, unsigned int);
static int parse_port(struct context *, const struct token *,
		      const char *, unsigned int,
		      void *, unsigned int);
static int parse_int(struct context *, const struct token *,
		     const char *, unsigned int,
		     void *, unsigned int);
static int
parse_ipv4_addr(struct context *ctx, const struct token *token,
		const char *str, unsigned int len,
		void *buf, unsigned int size);

static int
parse_default(struct context *ctx, const struct token *token,
	      const char *str, unsigned int len,
	      void *buf, unsigned int size);

static const struct token token_list[] = {

	[ZERO] = {
		.name = "ZERO",
		.next = NEXT(NEXT_ENTRY(FLOW)),
	},

	/* Top-level command. */
	[FLOW] = {
		.name = "flow",
		.type = "{command} {port_id} [{arg} [...]]",
		.next = NEXT(NEXT_ENTRY(CREATE)),
		.call = parse_init,
	},
	[CREATE] = {
		.name = "create",
		.next = NEXT(next_vc_attr, NEXT_ENTRY(COMMON_PORT_ID)),
		.args = ARGS(ARGS_ENTRY(struct buffer, port)),
		.call = parse_vc,
	},
	[COMMON_PORT_ID] = {
		.name = "{port_id}",
		.type = "PORT ID",
		.call = parse_port,
	},
	[VC_INGRESS] = {
		.name = "ingress",
		.next = NEXT(next_vc_attr),
		.call = parse_vc,
	},

	[ACTION_DROP] = {
		.name = "drop",
		.priv = PRIV_ACTION(DROP, 0),
		.next = NEXT(NEXT_ENTRY(ACTION_END)),
		.call = parse_vc,
	},
	
	[COMMON_IPV4_ADDR] = {
		.name = "{IPv4 address}",
		.type = "IPV4 ADDRESS",
		.call = parse_ipv4_addr,
	},

	/* Validate/create actions. */
	[ACTIONS] = {
		.name = "actions",
		.next = NEXT(next_action),
		.call = parse_vc,
	},
	[ACTION_NEXT] = {
		.name = "/",
		.next = NEXT(next_action),
	},
	[ACTION_END] = {
		.name = "end",
		.priv = PRIV_ACTION(END, 0),
		.call = parse_vc,
	},

	[ITEM_PATTERN] = {
		.name = "pattern",
		.next = NEXT(next_item),
		.call = parse_vc,
	},
	/* Validate/create pattern. */

	[ITEM_PARAM_IS] = {
		.name = "is",
		.call = parse_vc_spec,
	},
	[ITEM_PARAM_SPEC] = {
		.name = "spec",
		
		.call = parse_vc_spec,
	},
	[ITEM_PARAM_LAST] = {
		.name = "last",
		
		.call = parse_vc_spec,
	},
	[ITEM_PARAM_MASK] = {
		.name = "mask",
		
		.call = parse_vc_spec,
	},
	[ITEM_NEXT] = {
		.name = "/",
		
		.next = NEXT(next_item),
	},
    [ITEM_END] = {
		.name = "end",
		.priv = PRIV_ITEM(END, 0),
		.next = NEXT(NEXT_ENTRY(ACTIONS, END)),
		.call = parse_vc,
	},
	[ITEM_VOID] = {
		.name = "void",
		
		.priv = PRIV_ITEM(VOID, 0),
		.next = NEXT(NEXT_ENTRY(ITEM_NEXT)),
		.call = parse_vc,
	},

	[ITEM_ANY] = {
		.name = "any",
		
		.priv = PRIV_ITEM(ANY, sizeof(struct rte_flow_item_any)),
		.next = NEXT(item_any),
		.call = parse_vc,
	},
	[ITEM_PORT_ID] = {
		.name = "port_id",
		
		.priv = PRIV_ITEM(PORT_ID,
				  sizeof(struct rte_flow_item_port_id)),
		.next = NEXT(item_port_id),
		.call = parse_vc,
	},
	// [ITEM_RAW] = {
	// 	.name = "raw",
		
	// 	.priv = PRIV_ITEM(RAW, ITEM_RAW_SIZE),
	// 	.next = NEXT(next_item),
	// 	.call = parse_vc,
	// },
	[ITEM_ETH] = {
		.name = "eth",
		
		.priv = PRIV_ITEM(ETH, sizeof(struct rte_flow_item_eth)),
		.next = NEXT(item_eth),
		.call = parse_vc,
	},
	[ITEM_VLAN] = {
		.name = "vlan",
		
		.priv = PRIV_ITEM(VLAN, sizeof(struct rte_flow_item_vlan)),
		.next = NEXT(item_vlan),
		.call = parse_vc,
	},
	[ITEM_IPV4] = {
		.name = "ipv4",
		
		.priv = PRIV_ITEM(IPV4, sizeof(struct rte_flow_item_ipv4)),
		.next = NEXT(item_ipv4),
		.call = parse_vc,
	},
	[ITEM_IPV4_SRC] = {
		.name = "src",
		
		.next = NEXT(item_ipv4, NEXT_ENTRY(COMMON_IPV4_ADDR),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_ipv4,
					     hdr.src_addr)),
	},
	[ITEM_IPV4_DST] = {
		.name = "dst",
		
		.next = NEXT(item_ipv4, NEXT_ENTRY(COMMON_IPV4_ADDR),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_ipv4,
					     hdr.dst_addr)),
	},
	[ITEM_IPV6] = {
		.name = "ipv6",
		
		.priv = PRIV_ITEM(IPV6, sizeof(struct rte_flow_item_ipv6)),
		.next = NEXT(item_ipv6),
		.call = parse_vc,
	},
	[ITEM_IPV6_SRC] = {
		.name = "src",
		
		.next = NEXT(item_ipv6, NEXT_ENTRY(COMMON_IPV6_ADDR),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_ipv6,
					     hdr.src_addr)),
	},
	[ITEM_IPV6_DST] = {
		.name = "dst",
		
		.next = NEXT(item_ipv6, NEXT_ENTRY(COMMON_IPV6_ADDR),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_ipv6,
					     hdr.dst_addr)),
	},
	[ITEM_ICMP] = {
		.name = "icmp",
		
		.priv = PRIV_ITEM(ICMP, sizeof(struct rte_flow_item_icmp)),
		.next = NEXT(item_icmp),
		.call = parse_vc,
	},
	[ITEM_UDP] = {
		.name = "udp",
		
		.priv = PRIV_ITEM(UDP, sizeof(struct rte_flow_item_udp)),
		.next = NEXT(item_udp),
		.call = parse_vc,
	},
	[ITEM_UDP_SRC] = {
		.name = "src",
		
		.next = NEXT(item_udp, NEXT_ENTRY(COMMON_UNSIGNED),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_udp,
					     hdr.src_port)),
	},
	[ITEM_UDP_DST] = {
		.name = "dst",
		
		.next = NEXT(item_udp, NEXT_ENTRY(COMMON_UNSIGNED), item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_udp,
					     hdr.dst_port)),
	},
	[ITEM_TCP] = {
		.name = "tcp",
		
		.priv = PRIV_ITEM(TCP, sizeof(struct rte_flow_item_tcp)),
		.next = NEXT(item_tcp),
		.call = parse_vc,
	},
	[ITEM_TCP_SRC] = {
		.name = "src",
		
		.next = NEXT(item_tcp, NEXT_ENTRY(COMMON_UNSIGNED), item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_tcp,
					     hdr.src_port)),
	},
	[ITEM_TCP_DST] = {
		.name = "dst",
		
		.next = NEXT(item_tcp, NEXT_ENTRY(COMMON_UNSIGNED), item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_tcp,
					     hdr.dst_port)),
	},
	[ITEM_SCTP] = {
		.name = "sctp",
		
		.priv = PRIV_ITEM(SCTP, sizeof(struct rte_flow_item_sctp)),
		.next = NEXT(item_sctp),
		.call = parse_vc,
	},
	[ITEM_SCTP_SRC] = {
		.name = "src",
		
		.next = NEXT(item_sctp, NEXT_ENTRY(COMMON_UNSIGNED),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_sctp,
					     hdr.src_port)),
	},
	[ITEM_SCTP_DST] = {
		.name = "dst",
		
		.next = NEXT(item_sctp, NEXT_ENTRY(COMMON_UNSIGNED),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_sctp,
					     hdr.dst_port)),
	},
	[ITEM_VXLAN] = {
		.name = "vxlan",
		
		.priv = PRIV_ITEM(VXLAN, sizeof(struct rte_flow_item_vxlan)),
		.next = NEXT(item_vxlan),
		.call = parse_vc,
	},
	[ITEM_E_TAG] = {
		.name = "e_tag",
		
		.priv = PRIV_ITEM(E_TAG, sizeof(struct rte_flow_item_e_tag)),
		.next = NEXT(item_e_tag),
		.call = parse_vc,
	},
	[ITEM_NVGRE] = {
		.name = "nvgre",
		
		.priv = PRIV_ITEM(NVGRE, sizeof(struct rte_flow_item_nvgre)),
		.next = NEXT(item_nvgre),
		.call = parse_vc,
	},
	[ITEM_MPLS] = {
		.name = "mpls",
		
		.priv = PRIV_ITEM(MPLS, sizeof(struct rte_flow_item_mpls)),
		.next = NEXT(item_mpls),
		.call = parse_vc,
	},
	[ITEM_GRE] = {
		.name = "gre",
		
		.priv = PRIV_ITEM(GRE, sizeof(struct rte_flow_item_gre)),
		.next = NEXT(item_gre),
		.call = parse_vc,
	},
	[ITEM_FUZZY] = {
		.name = "fuzzy",
		
		.priv = PRIV_ITEM(FUZZY,
				sizeof(struct rte_flow_item_fuzzy)),
		.next = NEXT(item_fuzzy),
		.call = parse_vc,
	},

	[ITEM_GTP] = {
		.name = "gtp",
		
		.priv = PRIV_ITEM(GTP, sizeof(struct rte_flow_item_gtp)),
		.next = NEXT(item_gtp),
		.call = parse_vc,
	},

	[ITEM_GTPC] = {
		.name = "gtpc",
		
		.priv = PRIV_ITEM(GTPC, sizeof(struct rte_flow_item_gtp)),
		.next = NEXT(item_gtpc),
		.call = parse_vc,
	},
	[ITEM_GTPU] = {
		.name = "gtpu",
		
		.priv = PRIV_ITEM(GTPU, sizeof(struct rte_flow_item_gtp)),
		.next = NEXT(item_gtpu),
		.call = parse_vc,
	},
	[ITEM_GENEVE] = {
		.name = "geneve",
		
		.priv = PRIV_ITEM(GENEVE, sizeof(struct rte_flow_item_geneve)),
		.next = NEXT(item_geneve),
		.call = parse_vc,
	},
	[ITEM_VXLAN_GPE] = {
		.name = "vxlan-gpe",
		
		.priv = PRIV_ITEM(VXLAN_GPE,
				  sizeof(struct rte_flow_item_vxlan_gpe)),
		.next = NEXT(item_vxlan_gpe),
		.call = parse_vc,
	},

	[ITEM_ICMP6] = {
		.name = "icmp6",
		
		.priv = PRIV_ITEM(ICMP6, sizeof(struct rte_flow_item_icmp6)),
		.next = NEXT(item_icmp6),
		.call = parse_vc,
	},

};
/** Helper of get item's default mask. */
static const void *
flow_item_default_mask(const struct rte_flow_item *item)
{
	const void *mask = NULL;

	switch (item->type) {
	case RTE_FLOW_ITEM_TYPE_ANY:
		mask = &rte_flow_item_any_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_PORT_ID:
		mask = &rte_flow_item_port_id_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_RAW:
		mask = &rte_flow_item_raw_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_ETH:
		mask = &rte_flow_item_eth_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_VLAN:
		mask = &rte_flow_item_vlan_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_IPV4:
		mask = &rte_flow_item_ipv4_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6:
		mask = &rte_flow_item_ipv6_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP:
		mask = &rte_flow_item_icmp_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_UDP:
		mask = &rte_flow_item_udp_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_TCP:
		mask = &rte_flow_item_tcp_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_SCTP:
		mask = &rte_flow_item_sctp_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_VXLAN:
		mask = &rte_flow_item_vxlan_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_E_TAG:
		mask = &rte_flow_item_e_tag_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_NVGRE:
		mask = &rte_flow_item_nvgre_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_MPLS:
		mask = &rte_flow_item_mpls_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_GRE:
		mask = &rte_flow_item_gre_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_FUZZY:
		mask = &rte_flow_item_fuzzy_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_GTP:
		mask = &rte_flow_item_gtp_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_GENEVE:
		mask = &rte_flow_item_geneve_mask;
		break;
	default:
		break;
	}
	return mask;
}

/** Remove and return last entry from argument stack. */
static const struct arg *
pop_args(struct context *ctx)
{
	return ctx->args_num ? ctx->args[--ctx->args_num] : NULL;
}

/** Add entry on top of the argument stack. */
static int
push_args(struct context *ctx, const struct arg *arg)
{
	if (ctx->args_num == CTX_STACK_SIZE)
		return -1;
	ctx->args[ctx->args_num++] = arg;
	return 0;
}

/** Spread value into buffer according to bit-mask. */
static size_t
arg_entry_bf_fill(void *dst, uintmax_t val, const struct arg *arg)
{
	uint32_t i = arg->size;
	uint32_t end = 0;
	int sub = 1;
	int add = 0;
	size_t len = 0;

	if (!arg->mask)
		return 0;
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	if (!arg->hton) {
		i = 0;
		end = arg->size;
		sub = 0;
		add = 1;
	}
#endif
	while (i != end) {
		unsigned int shift = 0;
		uint8_t *buf = (uint8_t *)dst + arg->offset + (i -= sub);

		for (shift = 0; arg->mask[i] >> shift; ++shift) {
			if (!(arg->mask[i] & (1 << shift)))
				continue;
			++len;
			if (!dst)
				continue;
			*buf &= ~(1 << shift);
			*buf |= (val & 1) << shift;
			val >>= 1;
		}
		i += add;
	}
	return len;
}

/** Compare a string with a partial one of a given length. */
static int
strcmp_partial(const char *full, const char *partial, size_t partial_len)
{
	int r = strncmp(full, partial, partial_len);

	if (r)
		return r;
	if (strlen(full) <= partial_len)
		return 0;
	return full[partial_len];
}

/** Parse flow command, initialize output buffer for subsequent tokens. */
static int
parse_init(struct context *ctx, const struct token *token,
	   const char *str, unsigned int len,
	   void *buf, unsigned int size)
{
	struct buffer *out = buf;

	/* Token name must match. */
	if (parse_default(ctx, token, str, len, NULL, 0) < 0)
		return -1;
	/* Nothing else to do if there is no buffer. */
	if (!out)
		return len;
	/* Make sure buffer is large enough. */
	if (size < sizeof(*out))
		return -1;
	/* Initialize buffer. */
	memset(out, 0x00, sizeof(*out));
	memset((uint8_t *)out + sizeof(*out), 0x22, size - sizeof(*out));
	ctx->objdata = 0;
	ctx->object = out;
	ctx->objmask = NULL;
	return len;
}


/**
 * Parse an IPv4 address.
 *
 * Last argument (ctx->args) is retrieved to determine storage size and
 * location.
 */
static int
parse_ipv4_addr(struct context *ctx, const struct token *token,
		const char *str, unsigned int len,
		void *buf, unsigned int size)
{
	const struct arg *arg = pop_args(ctx);
	char str2[len + 1];
	struct in_addr tmp;
	int ret;

	/* Argument is expected. */
	if (!arg)
		return -1;
	size = arg->size;
	/* Bit-mask fill is not supported. */
	if (arg->mask || size != sizeof(tmp))
		goto error;
	/* Only network endian is supported. */
	if (!arg->hton)
		goto error;
	memcpy(str2, str, len);
	str2[len] = '\0';
	ret = inet_pton(AF_INET, str2, &tmp);
	if (ret != 1) {
		/* Attempt integer parsing. */
		push_args(ctx, arg);
		return parse_int(ctx, token, str, len, buf, size);
	}
	if (!ctx->object)
		return len;
	buf = (uint8_t *)ctx->object + arg->offset;
	memcpy(buf, &tmp, size);
	if (ctx->objmask)
		memset((uint8_t *)ctx->objmask + arg->offset, 0xff, size);
	return len;
error:
	push_args(ctx, arg);
	return -1;
}

/**
 * Parse signed/unsigned integers 8 to 64-bit long.
 *
 * Last argument (ctx->args) is retrieved to determine integer type and
 * storage location.
 */
static int
parse_int(struct context *ctx, const struct token *token,
	  const char *str, unsigned int len,
	  void *buf, unsigned int size)
{
	const struct arg *arg = pop_args(ctx);
	uintmax_t u;
	char *end;

	(void)token;
	/* Argument is expected. */
	if (!arg)
		return -1;
	errno = 0;
	u = arg->sign ?
		(uintmax_t)strtoimax(str, &end, 0) :
		strtoumax(str, &end, 0);
	if (errno || (size_t)(end - str) != len)
		goto error;
	if (arg->bounded &&
	    ((arg->sign && ((intmax_t)u < (intmax_t)arg->min ||
			    (intmax_t)u > (intmax_t)arg->max)) ||
	     (!arg->sign && (u < arg->min || u > arg->max))))
		goto error;
	if (!ctx->object)
		return len;
	if (arg->mask) {
		if (!arg_entry_bf_fill(ctx->object, u, arg) ||
		    !arg_entry_bf_fill(ctx->objmask, -1, arg))
			goto error;
		return len;
	}
	buf = (uint8_t *)ctx->object + arg->offset;
	size = arg->size;
	if (u > RTE_LEN2MASK(size * CHAR_BIT, uint64_t))
		return -1;
objmask:
	switch (size) {
	case sizeof(uint8_t):
		*(uint8_t *)buf = u;
		break;
	case sizeof(uint16_t):
		*(uint16_t *)buf = arg->hton ? rte_cpu_to_be_16(u) : u;
		break;
	case sizeof(uint8_t [3]):
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
		if (!arg->hton) {
			((uint8_t *)buf)[0] = u;
			((uint8_t *)buf)[1] = u >> 8;
			((uint8_t *)buf)[2] = u >> 16;
			break;
		}
#endif
		((uint8_t *)buf)[0] = u >> 16;
		((uint8_t *)buf)[1] = u >> 8;
		((uint8_t *)buf)[2] = u;
		break;
	case sizeof(uint32_t):
		*(uint32_t *)buf = arg->hton ? rte_cpu_to_be_32(u) : u;
		break;
	case sizeof(uint64_t):
		*(uint64_t *)buf = arg->hton ? rte_cpu_to_be_64(u) : u;
		break;
	default:
		goto error;
	}
	if (ctx->objmask && buf != (uint8_t *)ctx->objmask + arg->offset) {
		u = -1;
		buf = (uint8_t *)ctx->objmask + arg->offset;
		goto objmask;
	}
	return len;
error:
	push_args(ctx, arg);
	return -1;
}

static int
parse_port(struct context *ctx, const struct token *token,
	   const char *str, unsigned int len,
	   void *buf, unsigned int size)
{
	struct buffer *out = &(struct buffer){ .port = 0 };
	int ret;

	if (buf)
		out = buf;
	else {
		ctx->objdata = 0;
		ctx->object = out;
		ctx->objmask = NULL;
		size = sizeof(*out);
	}
	ret = parse_int(ctx, token, str, len, out, size);
	if (ret >= 0)
		ctx->port = out->port;
	if (!buf)
		ctx->object = NULL;
	return ret;
}

/** Default parsing function for token name matching. */
static int
parse_default(struct context *ctx, const struct token *token,
	      const char *str, unsigned int len,
	      void *buf, unsigned int size)
{
	(void)ctx;
	(void)buf;
	(void)size;
	if (strcmp_partial(token->name, str, len))
		return -1;
	return len;
}

/** Parse tokens for validate/create commands. */
static int
parse_vc(struct context *ctx, const struct token *token,
	 const char *str, unsigned int len,
	 void *buf, unsigned int size)
{
	struct buffer *out = buf;
	uint8_t *data;
	uint32_t data_size;

	/* Token name must match. */
	if (parse_default(ctx, token, str, len, NULL, 0) < 0)
		return -1;
	/* Nothing else to do if there is no buffer. */
	if (!out)
		return len;
	if (!out->command) {
		if (ctx->curr != CREATE)
			return -1;
		if (sizeof(*out) > size)
			return -1;
		out->command = ctx->curr;
		ctx->objdata = 0;
		ctx->object = out;
		ctx->objmask = NULL;
		out->args.vc.data = (uint8_t *)out + size;
		return len;
	}
	ctx->objdata = 0;
	ctx->objmask = NULL;
	if (ctx->curr == VC_INGRESS) {
		out->args.vc.attr.ingress = 1;
		return len;
	}
	ctx->object = &out->args.vc.attr;
	if (ctx->curr == ITEM_PATTERN) {
		out->args.vc.pattern =
			(void *)RTE_ALIGN_CEIL((uintptr_t)(out + 1),
							sizeof(double));
		ctx->object = out->args.vc.pattern;
		ctx->objmask = NULL;
		return len;
	}
	if (ctx->curr == ITEM_END) {
		if ( out->command == CREATE && ctx->last)
			return -1;
	}
	if (ctx->curr == ACTIONS) {
		out->args.vc.actions = out->args.vc.pattern ?
			(void *)RTE_ALIGN_CEIL((uintptr_t)
					       (out->args.vc.pattern +
						out->args.vc.pattern_n),
					       sizeof(double)) :
			(void *)RTE_ALIGN_CEIL((uintptr_t)(out + 1),
					       sizeof(double));
		ctx->object = out->args.vc.actions;
		ctx->objmask = NULL;
		return len;
	}
	if (!token->priv) {
		return -1;
	}
	if (!out->args.vc.actions) {
		const struct parse_item_priv *priv = token->priv;
		struct rte_flow_item *item =
			out->args.vc.pattern + out->args.vc.pattern_n;

		data_size = priv->size * 3; /* spec, last, mask */
		data = (void *)RTE_ALIGN_FLOOR((uintptr_t)
					       (out->args.vc.data - data_size),
					       sizeof(double));
		if ((uint8_t *)item + sizeof(*item) > data)
			return -1;
		*item = (struct rte_flow_item){
			.type = priv->type,
		};
		++out->args.vc.pattern_n;
		ctx->object = item;
		ctx->objmask = NULL;
	} else {
		const struct parse_action_priv *priv = token->priv;
		struct rte_flow_action *action =
			out->args.vc.actions + out->args.vc.actions_n;

		data_size = priv->size; /* configuration */
		data = (void *)RTE_ALIGN_FLOOR((uintptr_t)
					       (out->args.vc.data - data_size),
					       sizeof(double));
		if ((uint8_t *)action + sizeof(*action) > data)
			return -1;
		*action = (struct rte_flow_action){
			.type = priv->type,
			.conf = data_size ? data : NULL,
		};
		++out->args.vc.actions_n;
		ctx->object = action;
		ctx->objmask = NULL;
	}
	memset(data, 0, data_size);
	out->args.vc.data = data;
	ctx->objdata = data_size;
	return len;
}

/** Parse pattern item parameter type. */
static int
parse_vc_spec(struct context *ctx, const struct token *token,
	      const char *str, unsigned int len,
	      void *buf, unsigned int size)
{
	struct buffer *out = buf;
	struct rte_flow_item *item;
	uint32_t data_size;
	int index;
	int objmask = 0;

	(void)size;
	/* Token name must match. */
	if (parse_default(ctx, token, str, len, NULL, 0) < 0)
		return -1;
	/* Parse parameter types. */
	switch (ctx->curr) {
		static const enum index prefix[] = NEXT_ENTRY(COMMON_PREFIX);

	case ITEM_PARAM_IS:
		index = 0;
		objmask = 1;
		break;
	case ITEM_PARAM_SPEC:
		index = 0;
		break;
	case ITEM_PARAM_LAST:
		index = 1;
		break;
	case ITEM_PARAM_MASK:
		index = 2;
		break;
	default:
		return -1;
	}
	/* Nothing else to do if there is no buffer. */
	if (!out)
		return len;
	if (!out->args.vc.pattern_n)
		return -1;
	item = &out->args.vc.pattern[out->args.vc.pattern_n - 1];
	data_size = ctx->objdata / 3; /* spec, last, mask */
	/* Point to selected object. */
	ctx->object = out->args.vc.data + (data_size * index);
	if (objmask) {
		ctx->objmask = out->args.vc.data + (data_size * 2); /* mask */
		item->mask = ctx->objmask;
	} else
		ctx->objmask = NULL;
	/* Update relevant item pointer. */
	*((const void **[]){ &item->spec, &item->last, &item->mask })[index] =
		ctx->object;
	return len;
}

/** Parse a token (cmdline API). */
static int
cmd_flow_parse(const char *src, void *result,
	       unsigned int size)
{
	struct context *ctx = &cmd_flow_context;
	const struct token *token;
	const enum index *list;
	int len;
	int i;

	token = &token_list[ctx->curr];
	/* Check argument length. */
	ctx->eol = 0;
	ctx->last = 1;
	for (len = 0; src[len]; ++len)
		if (src[len] == '#' || isspace(src[len]))
			break;
	if (!len)
		return -1;
	/* Last argument and EOL detection. */
	for (i = len; src[i]; ++i)
		if (src[i] == '#' || src[i] == '\r' || src[i] == '\n')
			break;
		else if (!isspace(src[i])) {
			ctx->last = 0;
			break;
		}
	for (; src[i]; ++i)
		if (src[i] == '\r' || src[i] == '\n') {
			ctx->eol = 1;
			break;
		}
	/* Initialize context if necessary. */
	if (!ctx->next_num) {
		if (!token->next)
			return 0;
		ctx->next[ctx->next_num++] = token->next[0];
	}
	/* Process argument through candidates. */
	ctx->prev = ctx->curr;
	list = ctx->next[ctx->next_num - 1];
	for (i = 0; list[i]; ++i) {
		const struct token *next = &token_list[list[i]];
		int tmp;

		ctx->curr = list[i];
		if (next->call)
			tmp = next->call(ctx, next, src, len, result, size);
		else
			tmp = parse_default(ctx, next, src, len, result, size);
		if (tmp == -1 || tmp != len)
			continue;
		token = next;
		break;
	}
	if (!list[i])
		return -1;
	--ctx->next_num;
	/* Push subsequent tokens if any. */
	if (token->next)
		for (i = 0; token->next[i]; ++i) {
			if (ctx->next_num == RTE_DIM(ctx->next))
				return -1;
			ctx->next[ctx->next_num++] = token->next[i];
		}
	/* Push arguments if any. */
	if (token->args)
		for (i = 0; token->args[i]; ++i) {
			if (ctx->args_num == RTE_DIM(ctx->args))
				return -1;
			ctx->args[ctx->args_num++] = token->args[i];
		}
	return len;
}

static int
flow_parse(const char *src, void *result, unsigned int size,
	   struct rte_flow_item **pattern)
{
    SCLogInfo("Entering flow_parse");
	int ret;
	struct context saved_flow_ctx = cmd_flow_context;

	memset(result, 0x00, sizeof(*result));
	memset((uint8_t *)result + sizeof(*result), 0x22, size - sizeof(*result));

	cmd_flow_context_init(&cmd_flow_context);
	do {
		ret = cmd_flow_parse(src, result, size);
		if (ret > 0) {
			src += ret;
			while (isspace(*src))
				src++;
		}
	} while (ret > 0 && strlen(src));
	cmd_flow_context = saved_flow_ctx;
	*pattern = ((struct buffer *)result)->args.vc.pattern;
	return (ret >= 0 && !strlen(src)) ? 0 : -1;
}

int ParsePattern(char *pattern, struct rte_flow_item **items) {
    uint8_t data[1024] = {};
    flow_parse(pattern, (void *)data, sizeof(data), items);
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
