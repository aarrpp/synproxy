/* (C) 2010- Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * It bases on ipt_REJECT.c
 */
#define DEBUG
#define pr_fmt(fmt) "SYNPROXY: " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/unaligned/access_ok.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Changli Gao <xiaosuo@gmail.com>");
MODULE_DESCRIPTION("Xtables: \"SYNPROXY\" target for IPv4");

/* depends on nf_conntrack_proto_tcp and syncookies */

enum {
	TCP_SEND_FLAG_NOTRACE	= 0x1,
	TCP_SEND_FLAG_SYNCOOKIE	= 0x2,
	TCP_SEND_FLAG_ACK2SYN	= 0x4,
};

struct syn_proxy_state {
	u16	seq_inited;
	__be16	window;
	u32	seq_diff;
};

static int get_mtu(const struct dst_entry *dst)
{
	int mtu;

	mtu = dst_mtu(dst);
	if (mtu)
		return mtu;

	return dst->dev ? dst->dev->mtu : 0;
}

static int get_advmss(const struct dst_entry *dst)
{
	int advmss;

	advmss = dst_metric(dst, RTAX_ADVMSS);
	if (advmss)
		return advmss;
	advmss = get_mtu(dst);
	if (advmss)
		return advmss - (sizeof(struct iphdr) + sizeof(struct tcphdr));

	return TCP_MSS_DEFAULT;
}

static int syn_proxy_route(struct sk_buff *skb, struct net *net, u16 *pmss)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;
	struct flowi fl = {};
	unsigned int type;
	int flags = 0;
	int err;
	u16 mss;

	type = inet_addr_type(net, iph->saddr);
	if (type != RTN_LOCAL) {
		type = inet_addr_type(net, iph->daddr);
		if (type == RTN_LOCAL)
			flags |= FLOWI_FLAG_ANYSRC;
	}

	if (type == RTN_LOCAL) {
		fl.nl_u.ip4_u.daddr = iph->daddr;
		fl.nl_u.ip4_u.saddr = iph->saddr;
		fl.nl_u.ip4_u.tos = RT_TOS(iph->tos);
		fl.flags = flags;
		if ((err = ip_route_output_key(net, &rt, &fl)) != 0)
			goto out;

		skb_dst_set(skb, &rt->u.dst);
	} else {
		/* non-local src, find valid iif to satisfy
		 * rp-filter when calling ip_route_input. */
		fl.nl_u.ip4_u.daddr = iph->saddr;
		if ((err = ip_route_output_key(net, &rt, &fl)) != 0)
			goto out;

		if ((err = ip_route_input(skb, iph->daddr, iph->saddr,
					  RT_TOS(iph->tos),
					  rt->u.dst.dev)) != 0) {
			dst_release(&rt->u.dst);
			goto out;
		}
		if (pmss) {
			mss = get_advmss(&rt->u.dst);
			if (*pmss > mss)
				*pmss = mss;
		}
		dst_release(&rt->u.dst);
	}

	err = skb_dst(skb)->error;
	if (!err && pmss) {
		mss = get_advmss(skb_dst(skb));
		if (*pmss > mss)
			*pmss = mss;
	}

out:
	return err;
}

static int tcp_send(__be32 src, __be32 dst, __be16 sport, __be16 dport,
		    u32 seq, u32 ack_seq, __be16 window, u16 mss,
		    __be32 tcp_flags, u8 tos, struct net_device *dev, int flags,
		    struct sk_buff *oskb)
{
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *th;
	int err, len;

	len = sizeof(*th);
	if (mss)
		len += TCPOLEN_MSS;

	skb = NULL;
	/* caller must give me a large enough oskb */
	if (oskb) {
		unsigned char *odata = oskb->data;

		if (skb_recycle_check(oskb, 0)) {
			oskb->data = odata;
			skb_reset_tail_pointer(oskb);
			skb = oskb;
			pr_debug("recycle skb\n");
		}
	}
	if (!skb) {
		skb = alloc_skb(LL_MAX_HEADER + sizeof(*iph) + len, GFP_ATOMIC);
		if (!skb) {
			err = -ENOMEM;
			goto out;
		}
		skb_reserve(skb, LL_MAX_HEADER);
	}

	skb_reset_network_header(skb);
	if (!(flags & TCP_SEND_FLAG_ACK2SYN) || skb != oskb) {
		iph = (struct iphdr *)skb_put(skb, sizeof(*iph));
		iph->version	= 4;
		iph->ihl	= sizeof(*iph) / 4;
		iph->tos	= tos;
		/* tot_len is set in ip_local_out() */
		iph->id		= 0;
		iph->frag_off	= htons(IP_DF);
		iph->protocol	= IPPROTO_TCP;
		iph->saddr	= src;
		iph->daddr	= dst;
		th = (struct tcphdr *)skb_put(skb, len);
		th->source	= sport;
		th->dest	= dport;
	} else {
		iph = (struct iphdr*)skb->data;
		iph->id		= 0;
		iph->frag_off	= htons(IP_DF);
		skb_put(skb, iph->ihl * 4 + len);
		th = (struct tcphdr*)(skb->data + iph->ihl * 4);
	}

	th->seq		= htonl(seq);
	th->ack_seq	= htonl(ack_seq);
	tcp_flag_word(th) = tcp_flags;
	th->doff	= len / 4;
	th->window	= window;
	th->urg_ptr	= 0;

	skb->protocol = htons(ETH_P_IP);
	if ((flags & TCP_SEND_FLAG_SYNCOOKIE) && mss)
		err = syn_proxy_route(skb, dev_net(dev), &mss);
	else
		err = syn_proxy_route(skb, dev_net(dev), NULL);
	if (err)
		goto err_out;

	if ((flags & TCP_SEND_FLAG_SYNCOOKIE)) {
		if (mss) {
			th->seq = htonl(__cookie_v4_init_sequence(dst, src,
								  dport, sport,
								  ack_seq - 1,
								  &mss));
		} else {
			mss = TCP_MSS_DEFAULT;
			th->seq = htonl(__cookie_v4_init_sequence(dst, src,
								  dport, sport,
								  ack_seq - 1,
								  &mss));
			mss = 0;
		}
	}

	if (mss)
		* (__force __be32 *)(th + 1) = htonl((TCPOPT_MSS << 24) |
						     (TCPOLEN_MSS << 16) |
						     mss);
	skb->ip_summed = CHECKSUM_PARTIAL;
	th->check = ~tcp_v4_check(len, src, dst, 0);
	skb->csum_start = (unsigned char *)th - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);

	if (!(flags & TCP_SEND_FLAG_ACK2SYN) || skb != oskb)
		iph->ttl	= dst_metric(skb_dst(skb), RTAX_HOPLIMIT);

	if (skb->len > get_mtu(skb_dst(skb))) {
		if (printk_ratelimit())
			pr_warning("%s has smaller mtu: %d\n",
				   skb_dst(skb)->dev->name,
				   get_mtu(skb_dst(skb)));
		err = -EINVAL;
		goto err_out;
	}

	if ((flags & TCP_SEND_FLAG_NOTRACE)) {
		skb->nfct = &nf_conntrack_untracked.ct_general;
		skb->nfctinfo = IP_CT_NEW;
		nf_conntrack_get(skb->nfct);
	}

	pr_debug("ip_local_out: %pI4n:%hu -> %pI4n:%hu (seq=%u, "
		 "ack_seq=%u mss=%hu flags=%x)\n", &src, ntohs(th->source),
		 &dst, ntohs(th->dest), ntohl(th->seq), ack_seq, mss,
		 ntohl(tcp_flags));

	err = ip_local_out(skb);
	if (err > 0)
		err = net_xmit_errno(err);

	pr_debug("ip_local_out: return with %d\n", err);
out:
	if (oskb && oskb != skb)
		kfree_skb(oskb);

	return err;

err_out:
	kfree_skb(skb);
	goto out;
}

static int get_mss(u8 *data, int len)
{
	u8 olen;

	while (len >= TCPOLEN_MSS) {
		switch (data[0]) {
		case TCPOPT_EOL:
			return 0;
		case TCPOPT_NOP:
			data++;
			len--;
			break;
		case TCPOPT_MSS:
			if (data[1] != TCPOLEN_MSS)
				return -EINVAL;
			return get_unaligned_be16(data + 2);
		default:
			olen = data[1];
			if (olen < 2 || olen > len)
				return -EINVAL;
			data += olen;
			len -= olen;
			break;
		}
	}

	return 0;
}

static DEFINE_PER_CPU(struct syn_proxy_state, syn_proxy_state);

/* syn_proxy_pre isn't under the protection of nf_conntrack_proto_tcp.c */
static int syn_proxy_pre(struct sk_buff *skb, struct nf_conn *ct,
			 struct tcphdr *th)
{
	struct syn_proxy_state *state;
	struct iphdr *iph;

	/* only support IPv4 now */
	iph = ip_hdr(skb);
	if (iph->version != 4)
		return NF_ACCEPT;

	if (!ct || !nf_ct_is_confirmed(ct)) {
		int ret;

		if (!th->syn && th->ack) {
			u16 mss;
			struct sk_buff *rec_skb;

			mss = cookie_v4_check_sequence(iph, th,
						       ntohl(th->ack_seq) - 1);
			if (!mss)
				return NF_ACCEPT;

			pr_debug("%pI4n:%hu -> %pI4n:%hu(mss=%hu)\n",
				 &iph->saddr, ntohs(th->source),
				 &iph->daddr, ntohs(th->dest), mss);

			if (skb_tailroom(skb) < TCPOLEN_MSS &&
			    skb->len < iph->ihl * 4 + sizeof(*th) + TCPOLEN_MSS)
				rec_skb = NULL;
			else
				rec_skb = skb;

			local_bh_disable();
			state = &__get_cpu_var(syn_proxy_state);
			state->seq_inited = 1;
			state->window = th->window;
			state->seq_diff = ntohl(th->ack_seq) - 1;
			if (rec_skb)
				tcp_send(iph->saddr, iph->daddr, 0, 0,
					 ntohl(th->seq) - 1, 0, th->window,
					 mss, TCP_FLAG_SYN, 0, skb->dev,
					 TCP_SEND_FLAG_ACK2SYN, rec_skb);
			else
				tcp_send(iph->saddr, iph->daddr, th->source,
					 th->dest, ntohl(th->seq) - 1, 0,
					 th->window, mss, TCP_FLAG_SYN,
					 iph->tos, skb->dev, 0, NULL);
			state->seq_inited = 0;
			local_bh_enable();

			if (!rec_skb)
				kfree_skb(skb);

			return NF_STOLEN;
		}

		if (!ct || !th->syn || th->ack)
			return NF_ACCEPT;

		ret = NF_ACCEPT;
		local_bh_disable();
		state = &__get_cpu_var(syn_proxy_state);
		if (state->seq_inited) {
			struct syn_proxy_state *nstate;

			nstate = nf_ct_ext_add(ct, NF_CT_EXT_SYNPROXY,
					       GFP_ATOMIC);
			if (nstate != NULL) {
				nstate->seq_inited = 0;
				nstate->window = state->window;
				nstate->seq_diff = state->seq_diff;
				pr_debug("seq_diff: %u\n", nstate->seq_diff);
			} else {
				ret = NF_DROP;
			}
		}
		local_bh_enable();

		return ret;
	}

	state = nf_ct_ext_find(ct, NF_CT_EXT_SYNPROXY);
	if (!state)
		return NF_ACCEPT;

	if (CTINFO2DIR(skb->nfctinfo) == IP_CT_DIR_ORIGINAL) {
		__be32 newack;

		/* don't need to mangle duplicate SYN packets */
		if (th->syn && !th->ack)
			return NF_ACCEPT;
		if (!skb_make_writable(skb, ip_hdrlen(skb) + sizeof(*th)))
			return NF_DROP;
		th = (struct tcphdr *)(skb->data + ip_hdrlen(skb));
		newack = htonl(ntohl(th->ack_seq) - state->seq_diff);
		inet_proto_csum_replace4(&th->check, skb, th->ack_seq, newack,
					 0);
		pr_debug("alter ack seq: %u -> %u\n",
			 ntohl(th->ack_seq), ntohl(newack));
		th->ack_seq = newack;
	} else {
		/* Simultaneous open ? Oh, no. The connection between
		 * client and us is established. */
		if (th->syn && !th->ack)
			return NF_DROP;
	}

	return NF_ACCEPT;
}

static int syn_proxy_mangle_pkt(struct sk_buff *skb, struct iphdr *iph,
				struct tcphdr *th, u32 seq_diff)
{
	__be32 new;
	int olen;

	if (skb->len < (iph->ihl + th->doff) * 4)
		return NF_DROP;
	if (!skb_make_writable(skb, (iph->ihl + th->doff) * 4))
		return NF_DROP;
	iph = (struct iphdr *)(skb->data);
	th = (struct tcphdr *)(skb->data + iph->ihl * 4);

	new = tcp_flag_word(th) & (~TCP_FLAG_SYN);
	inet_proto_csum_replace4(&th->check, skb, tcp_flag_word(th), new, 0);
	tcp_flag_word(th) = new;

	new = htonl(ntohl(th->seq) + seq_diff);
	inet_proto_csum_replace4(&th->check, skb, th->seq, new, 0);
	pr_debug("alter seq: %u -> %u\n", ntohl(th->seq), ntohl(new));
	th->seq = new;

	olen = th->doff - sizeof(*th) / 4;
	if (olen) {
		__be32 *opt;

		opt = (__force __be32 *)(th + 1);
#define TCPOPT_EOL_WORD ((TCPOPT_EOL << 24) + (TCPOPT_EOL << 16) + \
			 (TCPOPT_EOL << 8) + TCPOPT_EOL)
		inet_proto_csum_replace4(&th->check, skb, *opt, TCPOPT_EOL_WORD,
					 0);
		*opt = TCPOPT_EOL_WORD;
	}

	return NF_ACCEPT;
}

static int syn_proxy_post(struct sk_buff *skb, struct nf_conn *ct,
			  enum ip_conntrack_info ctinfo)
{
	struct syn_proxy_state *state;
	struct iphdr *iph;
	struct tcphdr *th;

	/* untraced packets don't have NF_CT_EXT_SYNPROXY ext, as they don't
	 * enter syn_proxy_pre() */
	state = nf_ct_ext_find(ct, NF_CT_EXT_SYNPROXY);
	if (state == NULL)
		return NF_ACCEPT;
	
	iph = ip_hdr(skb);
	if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(*th)))
		return NF_DROP;
	th = (struct tcphdr *)(skb->data + iph->ihl * 4);
	if (!state->seq_inited) {
		if (th->syn) {
			/* It must be from original direction, as the ones
			 * from the other side are dropped in function
			 * syn_proxy_pre() */
			if (!th->ack)
				return NF_ACCEPT;

			pr_debug("SYN-ACK %pI4n:%hu -> %pI4n:%hu "
				 "(seq=%u ack_seq=%u)\n",
				 &iph->saddr, ntohs(th->source), &iph->daddr,
				 ntohs(th->dest), ntohl(th->seq),
				 ntohl(th->ack_seq));

			/* SYN-ACK from reply direction with the protection
			 * of conntrack */
			spin_lock_bh(&ct->lock);
			if (!state->seq_inited) {
				state->seq_inited = 1;
				pr_debug("update seq_diff %u -> %u\n",
					 state->seq_diff,
					 state->seq_diff - ntohl(th->seq));
				state->seq_diff -= ntohl(th->seq);
			}
			spin_unlock_bh(&ct->lock);
			tcp_send(iph->daddr, iph->saddr, th->dest, th->source,
				 ntohl(th->ack_seq),
				 ntohl(th->seq) + 1 + state->seq_diff,
				 state->window, 0, TCP_FLAG_ACK, iph->tos,
				 skb->dev, 0, NULL);

			return syn_proxy_mangle_pkt(skb, iph, th,
						    state->seq_diff + 1);
		} else {
			__be32 newseq;

			if (!th->rst)
				return NF_ACCEPT;
			newseq = htonl(state->seq_diff + 1);
			inet_proto_csum_replace4(&th->check, skb, th->seq,
						 newseq, 0);
			pr_debug("alter RST seq: %u -> %u\n",
				 ntohl(th->seq), ntohl(newseq));
			th->seq = newseq;

			return NF_ACCEPT;
		}
	}

	/* ct should be in ESTABLISHED state, but if the ack packets from
	 * us are lost. */
	if (th->syn) {
		if (!th->ack)
			return NF_ACCEPT;

		tcp_send(iph->daddr, iph->saddr, th->dest, th->source,
			 ntohl(th->ack_seq),
			 ntohl(th->seq) + 1 + state->seq_diff,
			 state->window, 0, TCP_FLAG_ACK, iph->tos,
			 skb->dev, 0, NULL);

		return syn_proxy_mangle_pkt(skb, iph, th, state->seq_diff + 1);
	}

	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_REPLY) {
		__be32 newseq;

		newseq = htonl(ntohl(th->seq) + state->seq_diff);
		inet_proto_csum_replace4(&th->check, skb, th->seq, newseq, 0);
		pr_debug("alter seq: %u -> %u\n", ntohl(th->seq),
			 ntohl(newseq));
		th->seq = newseq;
	}

	return NF_ACCEPT;
}

static int tcp_process(struct sk_buff *skb)
{
	const struct iphdr *iph;
	const struct tcphdr *th;
	int err;
	u16 mss;

	iph = ip_hdr(skb);
	if (iph->frag_off & htons(IP_OFFSET))
		goto out;
	if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(*th)))
		goto out;
	th = (const struct tcphdr *)(skb->data + iph->ihl * 4);
	if (th->fin || th->rst || th->ack || !th->syn)
		goto out;

	if (nf_ip_checksum(skb, NF_INET_PRE_ROUTING, iph->ihl * 4, IPPROTO_TCP))
		goto out;
	mss = 0;
	if (th->doff > sizeof(*th) / 4) {
		if (!pskb_may_pull(skb, (iph->ihl + th->doff) * 4))
			goto out;
		err = get_mss((u8 *)(th + 1), th->doff * 4 - sizeof(*th));
		if (err < 0)
			goto out;
		if (err != 0)
			mss = err;
	} else if (th->doff != sizeof(*th) / 4)
		goto out;

	tcp_send(iph->daddr, iph->saddr, th->dest, th->source, 0,
		 ntohl(th->seq) + 1, 0, mss, TCP_FLAG_SYN | TCP_FLAG_ACK,
		 iph->tos, skb->dev,
		 TCP_SEND_FLAG_NOTRACE | TCP_SEND_FLAG_SYNCOOKIE, skb);

	return NF_STOLEN;

out:
	return NF_DROP;
}

static unsigned int synproxy_tg(struct sk_buff *skb,
				const struct xt_action_param *par)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	int ret;

	/* received from lo */
	ct = nf_ct_get(skb, &ctinfo);
	if (ct)
		return IPT_CONTINUE;

	local_bh_disable();
	if (!__get_cpu_var(syn_proxy_state).seq_inited)
		ret = tcp_process(skb);
	else
		ret = IPT_CONTINUE;
	local_bh_enable();

	return ret;
}

static struct xt_target synproxy_tg_reg __read_mostly = {
	.name		= "SYNPROXY",
	.family		= NFPROTO_IPV4,
	.target		= synproxy_tg,
	.table		= "raw",
	.hooks		= (1 << NF_INET_PRE_ROUTING),
	.proto		= IPPROTO_TCP,
	.me		= THIS_MODULE,
};

static struct nf_ct_ext_type syn_proxy_state_ext __read_mostly = {
	.len	= sizeof(struct syn_proxy_state),
	.align	= __alignof__(struct syn_proxy_state),
	.id	= NF_CT_EXT_SYNPROXY,
};

static int __init synproxy_tg_init(void)
{
	int err, cpu;

	for_each_possible_cpu(cpu)
		per_cpu(syn_proxy_state, cpu).seq_inited = 0;
	rcu_assign_pointer(syn_proxy_pre_hook, syn_proxy_pre);
	rcu_assign_pointer(syn_proxy_post_hook, syn_proxy_post);
	err = nf_ct_extend_register(&syn_proxy_state_ext);
	if (err)
		goto err_out;
	err = xt_register_target(&synproxy_tg_reg);
	if (err)
		goto err_out2;

	return err;

err_out2:
	nf_ct_extend_unregister(&syn_proxy_state_ext);
err_out:
	rcu_assign_pointer(syn_proxy_post_hook, NULL);
	rcu_assign_pointer(syn_proxy_pre_hook, NULL);
	rcu_barrier();

	return err;
}

static void __exit synproxy_tg_exit(void)
{
	xt_unregister_target(&synproxy_tg_reg);
	nf_ct_extend_unregister(&syn_proxy_state_ext);
	rcu_assign_pointer(syn_proxy_post_hook, NULL);
	rcu_assign_pointer(syn_proxy_pre_hook, NULL);
	rcu_barrier();
}

module_init(synproxy_tg_init);
module_exit(synproxy_tg_exit);
