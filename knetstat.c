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

// Labels corresponding to the TCP states defined in tcp_states.h
static const char *const tcp_state_names[] = {
		"NONE",
		"ESTABLISHED",
		"SYN_SENT",
		"SYN_RECV",
		"FIN_WAIT1",
		"FIN_WAIT2",
		"TIME_WAIT",
		"CLOSE",
		"CLOSE_WAIT",
		"LAST_ACK",
		"LISTEN",
		"CLOSING",
};

static int tcp4_seq_show(struct seq_file *seq, void *v) {
	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "Proto Recv-Q Send-Q Local Address           Foreign Address         State       Options\n");
	} else {
		struct tcp_iter_state *st = seq->private;
		int pos;
		int len;

		int rx_queue;
		int tx_queue;
		__be32 dest;
		__be32 src;
		__u16 destp;
		__u16 srcp;
		int state;
		struct sock *sk;

		switch (st->state) {
			case TCP_SEQ_STATE_LISTENING:
			case TCP_SEQ_STATE_ESTABLISHED: {
				const struct tcp_sock *tp;
				const struct inet_sock *inet;

				sk = v;
				tp = tcp_sk(sk);
				inet = inet_sk(sk);

				// See get_tcp4_sock in tcp_ipv4.c
				if (sk->sk_state == TCP_LISTEN) {
					rx_queue = sk->sk_ack_backlog;
				} else {
					rx_queue = max_t(int, tp->rcv_nxt - tp->copied_seq, 0);
				}
				tx_queue = tp->write_seq - tp->snd_una;
				dest = inet->inet_daddr;
				src = inet->inet_rcv_saddr;
				destp = ntohs(inet->inet_dport);
				srcp = ntohs(inet->inet_sport);
				state = sk->sk_state;

				break;
			}
			case TCP_SEQ_STATE_OPENREQ: {
				const struct inet_request_sock *ireq = inet_rsk(v);

				// See get_openreq4 in tcp_ipv4.c
				rx_queue = 0;
				tx_queue = 0;
				src = ireq->loc_addr;
				srcp = ntohs(inet_sk(st->syn_wait_sk)->inet_sport);
				dest = ireq->rmt_addr;
				destp = ntohs(ireq->rmt_port);
				state = TCP_SYN_RECV;
				sk = NULL;

				break;
			}
			case TCP_SEQ_STATE_TIME_WAIT: {
				const struct inet_timewait_sock *tw = v;

				// See get_timewait4_sock in tcp_ipv4.c
				rx_queue = 0;
				tx_queue = 0;
				dest = tw->tw_daddr;
				src = tw->tw_rcv_saddr;
				destp = ntohs(tw->tw_dport);
				srcp = ntohs(tw->tw_sport);
				state = tw->tw_substate;
				sk = NULL;

				break;
			}
			default:
				return 0;
		}

		if (state < 0 || state >= TCP_MAX_STATES) {
			state = 0;
		}

		seq_printf(seq, "%-5s %6d %6d %pI4:%d%n", "tcp", rx_queue, tx_queue, &src, srcp, &pos);
		seq_printf(seq, "%*s", 44-pos, "");
		seq_printf(seq, "%pI4:%n", &dest, &len);
		pos = 44+len;
		if (destp == 0) {
			seq_printf(seq, "%s%n", "*", &len);
		} else {
			seq_printf(seq, "%d%n", destp, &len);
		}
		pos += len;
		seq_printf(seq, "%*s%-12s", 68-pos, "", tcp_state_names[state]);
		if (sk != NULL) {
			seq_printf(seq, "SO_REUSEADDR=%d,SO_KEEPALIVE=%d", sk->sk_reuse, sock_flag(sk, SOCK_KEEPOPEN));
		}
		seq_printf(seq, "\n");
	}
	return 0;
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
