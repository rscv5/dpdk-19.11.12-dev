#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <rte_eal.h>

#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_bpf.h>
#include <rte_bpf_ethdev.h>

#include <rte_malloc.h>
#include "bpf_impl.h"
#include <sys/queue.h>
#include <errno.h>
#include <string.h>


#define RX_RING_SIZE 1024  // 接收环大小
#define TX_RING_SIZE 1024  // 发送环大小

#define NUM_MBUFS 8191  // mbuf中元素个数
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32 // burst收发包模式的一次完成多个数据包的收发

// static int hwts_dynfield_offset = -1;

// static inline rte_mbuf_timestamp_t *
// hwts_field(struct rte_mbuf *mbuf)
// {
//         return RTE_MBUF_DYNFIELD(mbuf,
//                         hwts_dynfield_offset, rte_mbuf_timestamp_t *);
// }

// typedef uint64_t tsc_t;
// static int tsc_dynfield_offset = -1;

// static inline tsc_t *
// tsc_field(struct rte_mbuf *mbuf)
// {
//         return RTE_MBUF_DYNFIELD(mbuf, tsc_dynfield_offset, tsc_t *);
// }

// static const char usage[] =
//         "%s EAL_ARGS -- [-t]\n";

static const struct rte_bpf_xsym bpf_xsym[] = {
        {
                .name = RTE_STR(stdout),
                .type = RTE_BPF_XTYPE_VAR,
                .var = {
                        .val = (void *)(uintptr_t)&stdout,
                        .desc = {
                                .type = RTE_BPF_ARG_PTR, // point to data buffer
                                .size = sizeof(stdout),
                        },
                },
        },
        {
                .name = RTE_STR(rte_pktmbuf_dump), //RTE_STR 获得字符串
                .type = RTE_BPF_XTYPE_FUNC,
                .func = {
                        .val = (void *)rte_pktmbuf_dump, 
                        .nb_args = 3, // 参数数量
                        .args = {  // 函数参数描述
                                [0] = {
                                        .type = RTE_BPF_ARG_RAW, //
                                        .size = sizeof(uintptr_t),
                                },
                                [1] = {
                                        .type = RTE_BPF_ARG_PTR_MBUF, // point to rte_mbuf
                                        .size = sizeof(struct rte_mbuf),
                                },
                                [2] = {
                                        .type = RTE_BPF_ARG_RAW, // scalar value
                                        .size = sizeof(uint32_t),
                                },
                        },
                        
                },
        },
};
///////////////////////////////////////////////////////////////////////////////////
// 1. init struct rte_bpf_ethdev.h
HASHMBUF *hash_mbuf = NULL;

/*
 * Odd number means that callback is used by datapath.
 * Even number means that callback is not used by datapath.
 */
#define BPF_ETH_CBI_INUSE  1
#define __rte_noreturn __attribute__((noreturn))
/*
 * information about installed BPF rx/tx callback
 */

struct bpf_eth_cbi {
	/* used by both data & control path */
	uint32_t use;    /*usage counter */
	const struct rte_eth_rxtx_callback *cb;  /* callback handle */
	struct rte_bpf *bpf;
	struct rte_bpf_jit jit;
	/* used by control path only */
	LIST_ENTRY(bpf_eth_cbi) link;
	uint16_t port;
	uint16_t queue;
} __rte_cache_aligned;

/*
 * List to manage RX/TX installed callbacks.
 */
LIST_HEAD(bpf_eth_cbi_list, bpf_eth_cbi);

enum {
	BPF_ETH_RX,
	BPF_ETH_TX,
	BPF_ETH_NUM,
};

/*
 * information about all installed BPF rx/tx callbacks
 */
struct bpf_eth_cbh {
	rte_spinlock_t lock;
	struct bpf_eth_cbi_list list;
	uint32_t type;
};

static struct bpf_eth_cbh rx_cbh = {
	.lock = RTE_SPINLOCK_INITIALIZER,
	.list = LIST_HEAD_INITIALIZER(list),
	.type = BPF_ETH_RX,
};

/*
 * Marks given callback as used by datapath.
 */
static __rte_always_inline void
bpf_eth_cbi_inuse(struct bpf_eth_cbi *cbi)
{
	cbi->use++;
	/* make sure no store/load reordering could happen */
	rte_smp_mb();
}

/*
 * Marks given callback list as not used by datapath.
 */
static __rte_always_inline void
bpf_eth_cbi_unuse(struct bpf_eth_cbi *cbi)
{
	/* make sure all previous loads are completed */
	rte_smp_rmb();
	cbi->use++;
}

/*
 * Waits till datapath finished using given callback.
 */
static void
bpf_eth_cbi_wait(const struct bpf_eth_cbi *cbi)
{
	uint32_t nuse, puse;

	/* make sure all previous loads and stores are completed */
	rte_smp_mb();

	puse = cbi->use;

	/* in use, busy wait till current RX/TX iteration is finished */
	if ((puse & BPF_ETH_CBI_INUSE) != 0) {
		do {
			rte_pause();
			rte_compiler_barrier();
			nuse = cbi->use;
		} while (nuse == puse);
	}
}

static void
bpf_eth_cbi_cleanup(struct bpf_eth_cbi *bc)
{
	bc->bpf = NULL;
	memset(&bc->jit, 0, sizeof(bc->jit));
}

static struct bpf_eth_cbi *
bpf_eth_cbh_find(struct bpf_eth_cbh *cbh, uint16_t port, uint16_t queue)
{
	struct bpf_eth_cbi *cbi;

	LIST_FOREACH(cbi, &cbh->list, link) {
		if (cbi->port == port && cbi->queue == queue)
			break;
	}
	return cbi;
}


static struct bpf_eth_cbi *
bpf_eth_cbh_add(struct bpf_eth_cbh *cbh, uint16_t port, uint16_t queue)
{
	struct bpf_eth_cbi *cbi;

	/* return an existing one */
	cbi = bpf_eth_cbh_find(cbh, port, queue);
	if (cbi != NULL)
		return cbi;

	cbi = rte_zmalloc(NULL, sizeof(*cbi), RTE_CACHE_LINE_SIZE);
	if (cbi != NULL) {
		cbi->port = port;
		cbi->queue = queue;
		LIST_INSERT_HEAD(&cbh->list, cbi, link);
	}
	return cbi;
}


// 2. BPF packet processing routines
static inline uint32_t
apply_filter_test(struct rte_mbuf *mb[], const uint64_t rc[], uint32_t num,
    uint32_t drop)
{
    uint32_t i, j, k;
    struct rte_mbuf *dr[num];
    
    for(i = 0, j = 0, k = 0; i != num; i++){
        // filter matches
        if(rc[i] != 0)
            mb[j++] = mb[i];
        // no match
        else
            dr[k++] = mb[i];
    }

    if(drop != 0){
        // free filtered out mbufs
        for(i = 0; i != k; i++)
            rte_pktmbuf_free(dr[i]);
    } else {
        // copy filtered out mbuf beyond good ones
        for(i = 0; i != k; i++)
            mb[j + i] = dr[i];
    }

    return j;
}

// 3. pkt_jit
static inline uint32_t
pkt_jit(const struct rte_bpf_jit *jit, struct rte_mbuf *mb[], 
    uint32_t num,uint32_t drop)
{
    uint32_t i, n;
    void *dp;
    uint64_t rc[num]; // 是否丢包flag

    n = 0;
    // 遍历
    for(i = 0; i != num; i++){
        dp = rte_pktmbuf_mtod(mb[i], void *);
        hash_mbuf->mbuf = dp;
        hash_mbuf->hash_key = NULL;
        rc[i] = jit->func(hash_mbuf);
        n += (rc[i] == 0);
    }

    if(n != 0)
        num = apply_filter_test(mb, rc, num, drop);
    return num;
}

// 4. bpf_rx_callback_jit_test
static uint16_t
bpf_rx_callback_jit_test(__rte_unused uint16_t port, __rte_unused uint16_t queue,
    struct rte_mbuf *pkt[], uint16_t nb_pkts,
    __rte_unused uint16_t max_pkts, void *user_param)
{
    struct bpf_eth_cbi *cbi;
    uint16_t rc;

    cbi = user_param;
    bpf_eth_cbi_inuse(cbi);
    rc = (cbi->cb != NULL)?
        pkt_jit(&cbi->jit, pkt, nb_pkts, 1):
        nb_pkts;
    bpf_eth_cbi_unuse(cbi);
    return rc;
}

// 返回回调函数指针
static rte_rx_callback_fn
select_rx_callback(enum rte_bpf_arg_type type, uint32_t flags)
{
	if (flags & RTE_BPF_ETH_F_JIT) { // jit
		if (type == RTE_BPF_ARG_PTR) // pointer to data buffer
			return bpf_rx_callback_jit_test; 
        else return NULL;
    }
	return NULL;
}

/*
 * helper function to perform BPF unload for given port/queue.
 * have to introduce extra complexity (and possible slowdown) here,
 * as right now there is no safe generic way to remove RX/TX callback
 * while IO is active.
 * Still don't free memory allocated for callback handle itself,
 * again right now there is no safe way to do that without stopping RX/TX
 * on given port/queue first.
 */
static void
bpf_eth_cbi_unload(struct bpf_eth_cbi *bc)
{
	/* mark this cbi as empty */
	bc->cb = NULL;
	rte_smp_mb();

	/* make sure datapath doesn't use bpf anymore, then destroy bpf */
	bpf_eth_cbi_wait(bc);
	rte_bpf_destroy(bc->bpf);
	bpf_eth_cbi_cleanup(bc);
}

// bpf_eth_unload
static void
bpf_eth_unload(struct bpf_eth_cbh *cbh, uint16_t port, uint16_t queue)
{
	struct bpf_eth_cbi *bc;

	bc = bpf_eth_cbh_find(cbh, port, queue);
	if (bc == NULL || bc->cb == NULL)
		return;

	if (cbh->type == BPF_ETH_RX)
		rte_eth_remove_rx_callback(port, queue, bc->cb);
	else
		rte_eth_remove_tx_callback(port, queue, bc->cb);

	bpf_eth_cbi_unload(bc);
}

// 5. bpf_eth_elf_load_test
static int
bpf_eth_elf_load_test(struct bpf_eth_cbh *cbh, uint16_t port, uint16_t queue,
    const struct rte_bpf_prm *prm, const char *fname, const char *sname,
    uint32_t flags)
{
    int32_t rc; // 返回值
	struct bpf_eth_cbi *bc; // information about installed BPF rx/tx callback
	struct rte_bpf *bpf; // bpf struct
	rte_rx_callback_fn frx; // rx callback function
	struct rte_bpf_jit jit; // jit struct

    frx = NULL;

    if (prm == NULL || rte_eth_dev_is_valid_port(port) == 0 ||
			queue >= RTE_MAX_QUEUES_PER_PORT)
		return -EINVAL; // linux errno.h 22 invalid argument
    
    cbh->type = BPF_ETH_RX;
    frx = select_rx_callback(prm->prog_arg.type, flags);
	//frx = (rte_rx_callback_fn)bpf_rx_callback_jit_test;

	if (frx == NULL) {
		RTE_BPF_LOG(ERR, "%s(%u, %u): no callback selected;\n",
			__func__, port, queue);
		return -EINVAL;
	}

    bpf = rte_bpf_elf_load(prm, fname, sname);
    if(frx == NULL){
        RTE_BPF_LOG(ERR, "%s(%u, %u): no callback selected;\n",
        __func__, port, queue);
        return -EINVAL;
    }

    bpf = rte_bpf_elf_load(prm, fname, sname);
    if(bpf == NULL)
        return -rte_errno;

    rte_bpf_get_jit(bpf, &jit);

    if((flags & RTE_BPF_ETH_F_JIT) != 0 && jit.func == NULL){
        RTE_BPF_LOG(ERR, "%s(%u, %u): no JIT generated;\n",
            __func__, port, queue);
        rte_bpf_destroy(bpf);
        return -ENOTSUP;
    }

    bc = bpf_eth_cbh_add(cbh, port, queue);
    if(bc == NULL)
        return -ENOMEM;
    
    if(bc->cb != NULL)
        bpf_eth_unload(cbh, port, queue);
    
    bc->bpf = bpf;
    bc->jit = jit;

    // if(cbh->type == BPF_ETH_RX)
    bc->cb = rte_eth_add_rx_callback(port, queue, frx, bc);

    if(bc->cb == NULL){
        rc = -rte_errno;
        rte_bpf_destroy(bpf);
        bpf_eth_cbi_cleanup(bc);       
    } else{
        rc = 0;
    }
    
    return rc;    
}

// 6. rte_bpf_eth_rx_elf_load_test
static int
rte_bpf_eth_rx_elf_load_test(uint16_t port, uint16_t queue,
    const struct rte_bpf_prm *prm, const char *fname, const char *sname,
    uint32_t flags)
{
    int32_t rc;
    struct bpf_eth_cbh *cbh;

    cbh = &rx_cbh;
    rte_spinlock_lock(&cbh->lock);
    rc = bpf_eth_elf_load_test(cbh, port, queue, prm, fname, sname, flags);
    rte_spinlock_unlock(&cbh->lock);

    return rc;
}
/////////////////////////////////////////////////////////////////////////////////


static void bpf_callback_rx(const char *fname, uint16_t port, uint16_t queue, const char *sname){
        int32_t rc;
        uint32_t flags;
        struct rte_bpf_prm prm;
        struct rte_bpf_arg arg;
        // struct hash_mbuf my_par; // rte_mbuf_core.h 

        flags = RTE_BPF_ETH_F_NONE;
        flags |= RTE_BPF_ETH_F_JIT;

        // arg.type = RTE_BPF_ARG_PTR_MBUF; // pointer to data buffer 
        // arg.size = sizeof(struct rte_mbuf);
        // arg.buf_size = RTE_MBUF_DEFAULT_BUF_SIZE; // 每个mbuf的数据缓冲区大小

        arg.type = RTE_BPF_ARG_PTR; // pointer to data buffer
        arg.size = sizeof(struct hash_mbuf);
        arg.buf_size = RTE_MBUF_DEFAULT_BUF_SIZE; // 每个mbuf的数据缓冲区的大小

        memset(&prm, 0, sizeof(prm));
        prm.xsym = bpf_xsym;
        prm.nb_xsym = RTE_DIM(bpf_xsym);
        prm.prog_arg = arg;

        //printf(">>>>>>>>>");
        // rc = rte_bpf_eth_rx_elf_load(port, queue, &prm, fname, sname, flags);
        // rte_bpf_ethdev.h bpf_load_test.c
        rc = rte_bpf_eth_rx_elf_load_test(port, queue, &prm, fname, sname, flags);
        printf("%d:%s\n",rc, strerror(-rc));       
}


#define MAC_ARG(p) p[0],p[1],p[2],p[3],p[4],p[5]
#define IP_ARG(q)  q[0],q[1],q[2]
static int64_t
prs_tcp(const struct iphdr *iph){
    struct tcphdr *tcph = (void *)(iph+1);
    printf("source:%d dest:%d\n", ntohs(tcph->source), ntohs(tcph->dest));
    return 0;
}

static int64_t
prs_ip(const struct ether_header *eth){
        struct iphdr *iph = (void *)(eth + 1);
        struct in_addr s;
        s.s_addr = iph->saddr;
        printf("\t src ip : %s ",inet_ntoa(s));
        s.s_addr = iph->daddr;
        printf("\t des ip : %s", inet_ntoa(s));
        //printf("\t protocol:%d \n", iph->protocol);
        switch(iph->protocol){
                case 0x06:
                        printf("\t protocol: TCP");
                        prs_tcp(iph);
                        break;
                case 0x11:
                        printf("\t protocol: UDP\n");
                        break;
                case 0x01:
                        printf("\t protocol: ICMP\n");
                        break;
                default:
                        break;
        }
        return 0;
}
static int64_t
entry(void *pkt){
        const struct rte_mbuf *mb;
        const struct ether_header *eth;
        mb = pkt;
        eth = rte_pktmbuf_mtod(mb, const struct ether_header *);
        // print mac_h_dest
        printf("\th_sest:%02x:%02x:%02x:%02x:%02x:%02x", MAC_ARG(eth->ether_shost));
        printf("\th_dest:%02x:%02x:%02x:%02x:%02x:%02x \n", MAC_ARG(eth->ether_dhost));
        //printf("\teth_type: %04x", (short)eth->ether_type);
        switch(htons(eth->ether_type)){
                case 0x0806:
                        printf("\tprotocol : ARP\n");
                        break;
                case 0x8035:
                        printf("\tprotocol : RARP\n");
                        break;
                case 0x0800:
                        // 解析IPV4
                        printf("\tprotocol: IPv4");
                        prs_ip(eth);
                        break;
                case 0x86DD:
                        printf("protocol : IPv6\n");
                default:
                        break;

        }
        return 0;
}

static uint16_t
ebpf_callback(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
                struct rte_mbuf **pkts, uint16_t nb_pkts,
                uint16_t max_pkts __rte_unused, void *_ __rte_unused)
{
        unsigned i;
        //uint64_t now = rte_rdtsc();
        // nb_pkts
        for (i = 0; i < nb_pkts; i++){
                entry(pkts[i]);
        }
                //pkts[i]->udata64 = now;
        return nb_pkts;
}



/*
 * Initialises a given port using global settings and with the rx buffers
 * coming from the mbuf_pool passed as parameter
 */

 /* Port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
        struct rte_eth_conf port_conf; 
        const uint16_t rx_rings = 1, tx_rings = 1; // 每个网口有多少rx和tx队列，这里都为1
        uint16_t nb_rxd = RX_RING_SIZE; // 接收环大小
        uint16_t nb_txd = TX_RING_SIZE; // 发送环大小
        int retval;
        uint16_t q;
        struct rte_eth_dev_info dev_info; // 用于获取以太网设备， setup queue时用到
        struct rte_eth_rxconf rxconf; 
        struct rte_eth_txconf txconf; // setup tx queue时用到

        if (!rte_eth_dev_is_valid_port(port)) // 检查设备的port_id 是否已经链接
                return -1;

        // 将port_conf的rte_eth_conf设为0
        memset(&port_conf, 0, sizeof(struct rte_eth_conf));

        // 查询以太网设备的信息 
        retval = rte_eth_dev_info_get(port, &dev_info);
        if (retval != 0) {
                printf("Error during getting device (port %u) info: %s\n",
                                port, strerror(-retval));

                return retval;
        }

        // if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        //         port_conf.txmode.offloads |=
        //                 RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

        // 配置设备网卡
        /* 四个参数：
                1. port id
                2. 要给该网卡配置多少个收包队列
                3. 要给该网卡配置多少个发包队列
                4. 结构体指针类型 rte_eth_conf *
            返回0，代表设备已经配置
        */
        retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
        if (retval != 0) 
                return retval;

        // 调控
        // 检查Rx和Tx描述符的数量是否满足以太网设备信息中的描述符限制，否则将它们调整为边界
        retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
        if (retval != 0) 
                return retval;

        rxconf = dev_info.default_rxconf;

        // 初始化接收队列
        /* 参数：
                1. port id
                2. 接收队列的索引 [0, rx_queue -1](在rte_eth_dev_configure配置)
                3. 为接收环分配的接收描述符数（环的大小）
                4. socket id（如果时NUMA架构，rte_eth_dev_socket_id(port)获取port
                   所对应的以太网设备所连接上的socket的id;若不是NUMA，该值可以是宏SOCKET_ID_ANY
                5. 指向rx queue的配置数据的指针
                6. 指向内存池mempool的指针，从中分配mbuf去操作队列
        */
        for (q = 0; q < rx_rings; q++) {
                retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                        rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
                if (retval < 0)
                        return retval;
        }

        txconf = dev_info.default_txconf;
        txconf.offloads = port_conf.txmode.offloads;

        // 初始化发送队列
        /* 参数：
                1. port id
                2. 发送队列的索引。[0, tx_queue - 1](在rte_eth_dev_configure中配置的）
                3. 为发送环分配的接收描述符数。（自定义环的大小）
                4. socket id
                5. 指向tx queue的配置数据的指针，结构体是rte_eth_txconf。
        */
        for (q = 0; q < tx_rings; q++) {
                retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                rte_eth_dev_socket_id(port), &txconf);
                if (retval < 0)
                        return retval;
        }

        // 启动设备
        // 包括启动设备的发送和接收单元
        retval  = rte_eth_dev_start(port);
        if (retval < 0)
                return retval;


        // // 获取MAC地址并输出
        // struct rte_ether_addr addr;

        // retval = rte_eth_macaddr_get(port, &addr);
        // if (retval < 0) {
        //         printf("Failed to get MAC address on port %u: %s\n",
        //                 port, rte_strerror(-retval));
        //         return retval;
        // }
        // printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
        //                 " %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
        //                 (unsigned)port,
        //                 RTE_ETHER_ADDR_BYTES(&addr));

        // retval = rte_eth_promiscuous_enable(port);
        // if (retval != 0)
        //         return retval;

        // fname, port, queue, sname
        bpf_callback_rx("/home/dpdk-stable-19.11.12/examples/bpf/t5.o", port, 0, ".text");
        

        /* RX and TX callbacks are added to the ports. 
                1. port id
                2. queue idx
                3. 回调函数的函数指针
                4. 传递给回调函数的参数指针
           返回值是一个指针，可以用于删除回调的API
         */
        rte_eth_add_rx_callback(port, 0, ebpf_callback, NULL);
        /* >8 End of RX and TX callbacks. */

        return 0;
}
/* >8 End of port initialization. */





/*
 * Main thread that does the work, reading from INPUT_PORT
 * and writing to OUTPUT_PORT
 */
static __rte_noreturn void
lcore_main(void)
{
        uint16_t port;
        /*
           Check that the port is on the same NUMA node as the polling thread
           for best performance.
           当有NUMA结构时，检查网口是否在同一个NUMA node节点上，
           只有在一个NUMA node上时线程轮询效率最好
        */
        RTE_ETH_FOREACH_DEV(port)
                if (rte_eth_dev_socket_id(port) > 0 &&
                                rte_eth_dev_socket_id(port) !=
                                                (int)rte_socket_id())
                        // 若以太网所在的NUMA socket号与当前线程所在的socket号不同，报warning
                        printf("WARNING, port %u is on remote NUMA node to "
                                        "polling thread.\n\tPerformance will "
                                        "not be optimal.\n", port);

        printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
                        rte_lcore_id());

        /* Main work of application loop */
        // 死循环处理数据包
        for (;;) {
                RTE_ETH_FOREACH_DEV(port) {
                        struct rte_mbuf *bufs[BURST_SIZE]; // 收到的包存在这里
                        // 收包函数：rte_eth_rx_burst
                        // 从以太网设备的接收队列中检索一连串（burst收发包机制）输入数据包
                        // 检索到的数据包存储在rte_mbuf结构中
                        /* 参数四个： 1. port id （收到哪个网口）
                                     2. 队列索引  （的哪一条队列）[0, tx_queue -1]
                                     3. 指向 rte_mbuf结构的 指针数组的地址（把收到的包存在哪里
                                     4. 接收的最大数据包数
                                rte_eth_rx_burst()是一个循环函数，从RX队列中收包达到设定的最大数量为止
                        */ 
                        // 返回实际收到的数据包
                        const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
                                        bufs, BURST_SIZE);
                        if (unlikely(nb_rx == 0)) 
                                continue;


                        // 发包函数： rte_eth_tx_burst
                        // 在由port id指示的以太网设备的传输队列（由索引指示）发送一连串输出数据包
                        /* 参数四个：1. port id (从哪个网口)
                                    2. 队列索引 (的哪条队列发出), [0, rx_queue-1]
                                    3. 指向要发送的数据包的 rte_mbuf结构的 指针数组 的地址（要发的包在哪
                                    4. 要发的数据包最大数据量
                                
                        */
                        const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
                                        bufs, nb_rx);

                        // free any unsent packets.
                        if (unlikely(nb_tx < nb_rx)) {
                                uint16_t buf;

                                for (buf = nb_tx; buf < nb_rx; buf++)
                                        rte_pktmbuf_free(bufs[buf]);
                        }
                }
        }
}

/* Main function, does initialisation and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
        struct rte_mempool *mbuf_pool; // 指向内存池结构的指针
        uint16_t nb_ports; // 网口个数
        uint16_t portid; // 网口号


        static const struct rte_mbuf_dynfield tsc_dynfield_desc = {
                .name = "example_bbdev_dynfield_tsc",
                .size = sizeof(tsc_t),
                .align = __alignof__(tsc_t),
        };

        /* init EAL */
        int ret = rte_eal_init(argc, argv);

        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
        argc -= ret;
        argv += ret;



        nb_ports = rte_eth_dev_count_avail(); // 获取网口数
        if(nb_ports < 1)
                rte_exit(EXIT_FAILURE, "Error: at least one port \n");
        // if (nb_ports < 2 || (nb_ports & 1))
        //         rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

        // dpdk用mbuf保存packet，mempool用于操作mbuf
        // 创建并初始化mbuf池
        // 1. mbuf的名字 “MBUF_POOL”; 2. mbuf中的元素个数(8191); 
        // 3. 每个核心的缓存大小，如果该参数为0 可以禁用缓存（250）
        // 4. 每个mbuf中的数据缓冲区大小
        // 5. 应分配内存的套接字标识符 
        // 返回值：分配成功时返回指向新分配的mempool的指针
        // 
        // mempool的指针会传给port_init函数,用于 setup rx queue
        mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
                RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (mbuf_pool == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

        // register space for a dynamic field in the mbuf structure.
        tsc_dynfield_offset =
                rte_mbuf_dynfield_register(&tsc_dynfield_desc);
        if (tsc_dynfield_offset < 0)
                rte_exit(EXIT_FAILURE, "Cannot register mbuf field\n");

        /* initialize all ports */
        // 使用RTE_ETH_FOREACH_DEV()循环遍历port网口
        // 将几个port托给dpdk管理,这里就执行几次
        RTE_ETH_FOREACH_DEV(portid)
                if (port_init(portid, mbuf_pool) != 0)
                        rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16"\n",
                                        portid);

        if (rte_lcore_count() > 1)
                printf("\nWARNING: Too much enabled lcores - "
                        "App uses only 1 lcore\n");

        /* call lcore_main on main core only */
        // 主线程调用
        lcore_main();

        /* clean up the EAL */
        rte_eal_cleanup();

        return 0;
}