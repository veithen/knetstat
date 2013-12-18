#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/types.h>
#include <net/tcp.h>
#include <net/tcp_states.h>

#include <net/net_namespace.h>

#define TMPSZ 150

static void get_tcp4_sock(struct sock *sk, struct seq_file *f, int i, int *len)
{
	int timer_active;
	unsigned long timer_expires;
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	struct fastopen_queue *fastopenq = icsk->icsk_accept_queue.fastopenq;
	__be32 dest = inet->inet_daddr;
	__be32 src = inet->inet_rcv_saddr;
	__u16 destp = ntohs(inet->inet_dport);
	__u16 srcp = ntohs(inet->inet_sport);
	int rx_queue;

	if (icsk->icsk_pending == ICSK_TIME_RETRANS ||
	    icsk->icsk_pending == ICSK_TIME_EARLY_RETRANS ||
	    icsk->icsk_pending == ICSK_TIME_LOSS_PROBE) {
		timer_active	= 1;
		timer_expires	= icsk->icsk_timeout;
	} else if (icsk->icsk_pending == ICSK_TIME_PROBE0) {
		timer_active	= 4;
		timer_expires	= icsk->icsk_timeout;
	} else if (timer_pending(&sk->sk_timer)) {
		timer_active	= 2;
		timer_expires	= sk->sk_timer.expires;
	} else {
		timer_active	= 0;
		timer_expires = jiffies;
	}

	if (sk->sk_state == TCP_LISTEN)
		rx_queue = sk->sk_ack_backlog;
	else
		/*
		 * because we dont lock socket, we might find a transient negative value
		 */
		rx_queue = max_t(int, tp->rcv_nxt - tp->copied_seq, 0);

	seq_printf(f, "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX "
			"%08X %5u %8d %lu %d %pK %lu %lu %u %u %d%n",
		i, src, srcp, dest, destp, sk->sk_state,
		tp->write_seq - tp->snd_una,
		rx_queue,
		timer_active,
		jiffies_delta_to_clock_t(timer_expires - jiffies),
		icsk->icsk_retransmits,
		from_kuid_munged(seq_user_ns(f), sock_i_uid(sk)),
		icsk->icsk_probes_out,
		sock_i_ino(sk),
		atomic_read(&sk->sk_refcnt), sk,
		jiffies_to_clock_t(icsk->icsk_rto),
		jiffies_to_clock_t(icsk->icsk_ack.ato),
		(icsk->icsk_ack.quick << 1) | icsk->icsk_ack.pingpong,
		tp->snd_cwnd,
		sk->sk_state == TCP_LISTEN ?
		    (fastopenq ? fastopenq->max_qlen : 0) :
		    (tcp_in_initial_slowstart(tp) ? -1 : tp->snd_ssthresh),
		len);
}

static void get_openreq4(const struct sock *sk, const struct request_sock *req,
			 struct seq_file *f, int i, kuid_t uid, int *len)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	long delta = req->expires - jiffies;

	seq_printf(f, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5u %8d %u %d %pK%n",
		i,
		ireq->loc_addr,
		ntohs(inet_sk(sk)->inet_sport),
		ireq->rmt_addr,
		ntohs(ireq->rmt_port),
		TCP_SYN_RECV,
		0, 0, /* could print option size, but that is af dependent. */
		1,    /* timers active (only the expire timer) */
		jiffies_delta_to_clock_t(delta),
		req->num_timeout,
		from_kuid_munged(seq_user_ns(f), uid),
		0,  /* non standard timer */
		0, /* open_requests have no inode */
		atomic_read(&sk->sk_refcnt),
		req,
		len);
}

static void get_timewait4_sock(const struct inet_timewait_sock *tw,
			       struct seq_file *f, int i, int *len)
{
	__be32 dest, src;
	__u16 destp, srcp;
	long delta = tw->tw_ttd - jiffies;

	dest  = tw->tw_daddr;
	src   = tw->tw_rcv_saddr;
	destp = ntohs(tw->tw_dport);
	srcp  = ntohs(tw->tw_sport);

	seq_printf(f, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %d %d %pK%n",
		i, src, srcp, dest, destp, tw->tw_substate, 0, 0,
		3, jiffies_delta_to_clock_t(delta), 0, 0, 0, 0,
		atomic_read(&tw->tw_refcnt), tw, len);
}

static int tcp4_seq_show(struct seq_file *seq, void *v) {
	struct tcp_iter_state *st;
	int len;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "%-*s\n", TMPSZ - 1,
				"  sl  local_address rem_address   st tx_queue "
						"rx_queue tr tm->when retrnsmt   uid  timeout "
						"inode");
		goto out;
	}
	st = seq->private;

	switch (st->state) {
	case TCP_SEQ_STATE_LISTENING:
	case TCP_SEQ_STATE_ESTABLISHED:
		get_tcp4_sock(v, seq, st->num, &len);
		break;
	case TCP_SEQ_STATE_OPENREQ:
		get_openreq4(st->syn_wait_sk, v, seq, st->num, st->uid, &len);
		break;
	case TCP_SEQ_STATE_TIME_WAIT:
		get_timewait4_sock(v, seq, st->num, &len);
		break;
	}
	seq_printf(seq, "%*s\n", TMPSZ - 1 - len, "");
	out: return 0;
}

static const struct file_operations tcp_afinfo_seq_fops = {
		.owner = THIS_MODULE, .open = tcp_seq_open, .read = seq_read, .llseek =
				seq_lseek, .release = seq_release_net };

static struct tcp_seq_afinfo tcp4_seq_afinfo = { .name = "tcpstat", .family =
		AF_INET, .seq_fops = &tcp_afinfo_seq_fops, .seq_ops = { .show =
		tcp4_seq_show, }, };

static int __net_init knetstat_net_init(struct net *net) {
	return tcp_proc_register(net, &tcp4_seq_afinfo);
}

static void __net_exit knetstat_net_exit(struct net *net) {
	tcp_proc_unregister(net, &tcp4_seq_afinfo);
}

static struct pernet_operations knetstat_net_ops = { .init = knetstat_net_init,
		.exit = knetstat_net_exit, };

static int knetstat_init(void) {
	int err;

	err = register_pernet_subsys(&knetstat_net_ops);
	if (err < 0)
		return err;

	return 0;
}

static void knetstat_exit(void) {
	unregister_pernet_subsys(&knetstat_net_ops);
}

module_init(knetstat_init)
module_exit(knetstat_exit)

MODULE_LICENSE("GPL");
