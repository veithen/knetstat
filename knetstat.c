/**
 * knetstat
 * Copyright (C) 2013-2017  Andreas Veithen
 * Copyright (C) 2014  Google
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/types.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/udp.h>

#include <net/net_namespace.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
#define tcp_time_stamp tcp_time_stamp_raw()
#endif

// Labels corresponding to the TCP states defined in tcp_states.h
static const char *const tcp_state_names[] = {
		"NONE",
		"ESTB",
		"SYNS",
		"SYNR",
		"FNW1",
		"FNW2",
		"TIMW",
		"CLSD",
		"CLSW",
		"LACK",
		"LSTN",
		"CLSG",
		"SYNR"
};

static void sock_common_options_show(struct seq_file *seq, struct sock *sk) {
	// Note:
	//  * Linux actually doubles the values for SO_RCVBUF and SO_SNDBUF (see sock_setsockopt in net/core/sock.c)
	//  * If these options are not set explicitly, the kernel may dynamically scale the buffer sizes
	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK) {
		seq_printf(seq, ",SO_RCVBUF=%d", sk->sk_rcvbuf / 2);
	}
	if (sk->sk_userlocks & SOCK_SNDBUF_LOCK) {
		seq_printf(seq, ",SO_SNDBUF=%d", sk->sk_sndbuf / 2);
	}

	if (sk->sk_rcvtimeo != MAX_SCHEDULE_TIMEOUT) {
		seq_printf(seq, ",SO_RCVTIMEO=%ldms", sk->sk_rcvtimeo*1000/HZ);
	}
	if (sk->sk_sndtimeo != MAX_SCHEDULE_TIMEOUT) {
		seq_printf(seq, ",SO_SNDTIMEO=%ldms", sk->sk_sndtimeo*1000/HZ);
	}

	if (sock_flag(sk, SOCK_LINGER)) {
		seq_printf(seq, ",SO_LINGER=%lds", sk->sk_lingertime / HZ);
	}
}

static void addr_port_show(struct seq_file *seq, sa_family_t family, const void* addr, __u16 port) {
	seq_setwidth(seq, 23);
	seq_printf(seq, family == AF_INET6 ? "%pI6c" : "%pI4", addr);
	if (port == 0) {
		seq_puts(seq, ":*");
	} else {
		seq_printf(seq, ":%d", port);
	}
	seq_pad(seq, ' ');
}

static int tcp_seq_show(struct seq_file *seq, void *v) {
	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "Recv-Q Send-Q Local Address           Foreign Address         Stat Diag Options\n");
	} else {
		struct tcp_iter_state *st = seq->private;
		sa_family_t family = st->family;

		int rx_queue;
		int tx_queue;
		const void *dest;
		const void *src;
		__u16 destp;
		__u16 srcp;
		int state;
		struct sock *sk;
		int fo_qlen = 0;
		u8 defer = 0;

		switch (st->state) {
			case TCP_SEQ_STATE_LISTENING:
			case TCP_SEQ_STATE_ESTABLISHED: {
				sk = v;
				if (sk->sk_state == TCP_TIME_WAIT) {
					const struct inet_timewait_sock *tw = v;

					// See get_timewait4_sock in tcp_ipv4.c and get_timewait6_sock in tcp_ipv6.c
					rx_queue = 0;
					tx_queue = 0;
					if (family == AF_INET6) {
						dest = &tw->tw_v6_daddr;
						src = &tw->tw_v6_rcv_saddr;
					} else {
						dest = &tw->tw_daddr;
						src = &tw->tw_rcv_saddr;
					}
					destp = ntohs(tw->tw_dport);
					srcp = ntohs(tw->tw_sport);
					state = tw->tw_substate;
					sk = NULL;
				} else {
					const struct tcp_sock *tp;
					const struct inet_sock *inet;
					const struct fastopen_queue *fq;

					tp = tcp_sk(sk);
					inet = inet_sk(sk);
					defer = inet_csk(sk)->icsk_accept_queue.rskq_defer_accept;

					// See get_tcp4_sock in tcp_ipv4.c and get_tcp6_sock in tcp_ipv6.c
					switch (sk->sk_state) {
						case TCP_LISTEN:
							rx_queue = sk->sk_ack_backlog;
							tx_queue = 0;
							fq = &inet_csk(sk)->icsk_accept_queue.fastopenq;
							if (fq != NULL) {
								fo_qlen = fq->max_qlen;
							}
							break;
						#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
						case TCP_NEW_SYN_RECV:
							rx_queue = 0;
							tx_queue = 0;
							break;
						#endif
						default:
							rx_queue = max_t(int, tp->rcv_nxt - tp->copied_seq, 0);
							tx_queue = tp->write_seq - tp->snd_una;
					}
					if (family == AF_INET6) {
						dest = &sk->sk_v6_daddr;
						src = &sk->sk_v6_rcv_saddr;
					} else {
						dest = &inet->inet_daddr;
						src = &inet->inet_rcv_saddr;
					}
					destp = ntohs(inet->inet_dport);
					srcp = ntohs(inet->inet_sport);
					state = sk->sk_state;
					#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
					if (sk->sk_state == TCP_NEW_SYN_RECV) {
						sk = NULL;
					}
					#endif
				}
				break;
			}
			#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
			case TCP_SEQ_STATE_OPENREQ: {
				const struct inet_request_sock *ireq = inet_rsk(v);

				// See get_openreq4 in tcp_ipv4.c and get_openreq6 in tcp_ipv6.c
				rx_queue = 0;
				tx_queue = 0;
				if (family == AF_INET6) {
					src = &ireq->ir_v6_loc_addr;
					dest = &ireq->ir_v6_rmt_addr;
				} else {
					src = &ireq->ir_loc_addr;
					dest = &ireq->ir_rmt_addr;
				}
				srcp = ntohs(inet_sk(st->syn_wait_sk)->inet_sport);
				destp = ntohs(ireq->ir_rmt_port);
				state = TCP_SYN_RECV;
				sk = NULL;

				break;
			}
			#endif
			default:
				return 0;
		}

		if (state < 0 || state >= TCP_MAX_STATES) {
			state = 0;
		}

		seq_printf(seq, "%6d %6d ", rx_queue, tx_queue);
		addr_port_show(seq, family, src, srcp);
		addr_port_show(seq, family, dest, destp);

		seq_printf(seq, "%s ", tcp_state_names[state]);
		if (sk != NULL) {
			seq_setwidth(seq, 4);
			if (state == TCP_ESTABLISHED) {
				const struct tcp_sock *tp = tcp_sk(sk);
				if (tp->rcv_wnd == 0 && tp->snd_wnd == 0) {
					// Both receiver and sender windows are 0; we can neither receive nor send more data
					seq_puts(seq, ">|<");
				} else if (tp->rcv_wnd == 0) {
					// Receiver window is 0; we cannot receive more data
					seq_puts(seq, "|<");
				} else if (tp->snd_wnd == 0) {
					// Sender window is 0; we cannot send more data
					seq_puts(seq, ">|");
				} else if (tp->snd_nxt > tp->snd_una && tcp_time_stamp-tp->rcv_tstamp > HZ) {
					// There are unacknowledged packets and the last ACK was received more than 1 second ago;
					// this is an indication for network problems
					seq_puts(seq, ">#");
				}
			}
			seq_pad(seq, ' ');


			seq_printf(seq, "SO_REUSEADDR=%d,SO_REUSEPORT=%d,SO_KEEPALIVE=%d", sk->sk_reuse, sk->sk_reuseport, sock_flag(sk, SOCK_KEEPOPEN));

			sock_common_options_show(seq, sk);

			seq_printf(seq, ",TCP_NODELAY=%d", !!(tcp_sk(sk)->nonagle&TCP_NAGLE_OFF));

			if (state == TCP_LISTEN) {
				seq_printf(seq, ",TCP_FASTOPEN=%d", fo_qlen);
			}

			seq_printf(seq, ",TCP_DEFER_ACCEPT=%d", defer);

		}
		seq_printf(seq, "\n");
	}
	return 0;
}

static const struct file_operations tcp_afinfo_seq_fops = {
		.owner = THIS_MODULE,
		.open = tcp_seq_open,
		.read = seq_read,
		.llseek = seq_lseek,
		.release = seq_release_net
};

static struct tcp_seq_afinfo tcp4_seq_afinfo = {
		.name = "tcpstat",
		.family = AF_INET,
		.seq_fops = &tcp_afinfo_seq_fops,
		.seq_ops = {
				.show = tcp_seq_show,
		},
};

static struct tcp_seq_afinfo tcp6_seq_afinfo = {
		.name = "tcp6stat",
		.family = AF_INET6,
		.seq_fops = &tcp_afinfo_seq_fops,
		.seq_ops = {
				.show = tcp_seq_show,
		},
};

static int udp_seq_show(struct seq_file *seq, void *v) {
	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "Recv-Q Send-Q Local Address           Foreign Address         Options\n");
	} else {
		struct udp_iter_state *st = seq->private;
		sa_family_t family = st->family;
		struct sock *sk = v;
		int tx_queue = sk_wmem_alloc_get(sk);
		int rx_queue = sk_rmem_alloc_get(sk);
		struct inet_sock *inet = inet_sk(sk);
		const void *dest;
		const void *src;
		__u16 destp;
		__u16 srcp;

		if (family == AF_INET6) {
			dest = &sk->sk_v6_daddr;
			src = &sk->sk_v6_rcv_saddr;
		} else {
			dest = &inet->inet_daddr;
			src = &inet->inet_rcv_saddr;
		}
		destp = ntohs(inet->inet_dport);
		srcp = ntohs(inet->inet_sport);

		seq_printf(seq, "%6d %6d ", rx_queue, tx_queue);
		addr_port_show(seq, family, src, srcp);
		addr_port_show(seq, family, dest, destp);

		seq_printf(seq, "SO_REUSEADDR=%d,SO_REUSEPORT=%d", sk->sk_reuse, sk->sk_reuseport);

		sock_common_options_show(seq, sk);

		seq_printf(seq, ",SO_BROADCAST=%d", sock_flag(sk, SOCK_BROADCAST));

		seq_printf(seq, "\n");
	}
	return 0;
}

static const struct file_operations udp_afinfo_seq_fops = {
		.owner = THIS_MODULE,
		.open = udp_seq_open,
		.read = seq_read,
		.llseek = seq_lseek,
		.release = seq_release_net
};

static struct udp_seq_afinfo udp4_seq_afinfo = {
		.name = "udpstat",
		.family = AF_INET,
		.udp_table = &udp_table,
		.seq_fops = &udp_afinfo_seq_fops,
		.seq_ops = {
				.show = udp_seq_show,
		},
};

static struct udp_seq_afinfo udp6_seq_afinfo = {
		.name = "udp6stat",
		.family = AF_INET6,
		.udp_table = &udp_table,
		.seq_fops = &udp_afinfo_seq_fops,
		.seq_ops = {
				.show = udp_seq_show,
		},
};

static int __net_init knetstat_net_init(struct net *net) {
	int ret;
	int registered = 0;

	ret = tcp_proc_register(net, &tcp4_seq_afinfo);
	if (ret < 0) {
		goto cleanup;
	}
	++registered;

	ret = tcp_proc_register(net, &tcp6_seq_afinfo);
	if (ret < 0) {
		goto cleanup;
	}
	++registered;

	ret = udp_proc_register(net, &udp4_seq_afinfo);
	if (ret < 0) {
		goto cleanup;
	}
	++registered;

	ret = udp_proc_register(net, &udp6_seq_afinfo);
	if (ret < 0) {
		goto cleanup;
	}

	return ret;
cleanup:
	if (registered > 2) {
		udp_proc_unregister(net, &udp4_seq_afinfo);
	}
	if (registered > 1) {
		tcp_proc_unregister(net, &tcp6_seq_afinfo);
	}
	if (registered > 0) {
		tcp_proc_unregister(net, &tcp4_seq_afinfo);
	}
	return ret;
}

static void __net_exit knetstat_net_exit(struct net *net) {
	tcp_proc_unregister(net, &tcp4_seq_afinfo);
	tcp_proc_unregister(net, &tcp6_seq_afinfo);
	udp_proc_unregister(net, &udp4_seq_afinfo);
	udp_proc_unregister(net, &udp6_seq_afinfo);
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
MODULE_AUTHOR("Andreas Veithen <andreas.veithen@gmail.com>");
MODULE_DESCRIPTION("Support for /proc/net/tcpstat and /proc/net/tcp6stat");
