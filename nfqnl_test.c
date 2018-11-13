#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <endian.h>	
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <python3.6/Python.h>

PyObject *pName, *pModule, *pDict, *pFunc, *pValue;



static u_int32_t print_pkt (struct nfq_data *tb)
{
	
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}
	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
//	u_int32_t id;


    struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);	
	id = ntohl(ph->packet_id);
	printf("entering callback\n");
	
	struct iphdr *ipHeader;
	unsigned char *payloadData;
	nfq_get_payload(nfa, &payloadData);
	ipHeader = (struct iphdr *)payloadData;
	
	//TODO: Ver se nao eh melhor com unsigned int
	uint32_t sourceIP = be32toh(ipHeader->saddr);
	uint32_t destIP = be32toh(ipHeader->daddr);
	//printf("IP = %04x\n", ip);
	
	if(ipHeader->protocol == IPPROTO_TCP){
		struct tcphdr *tcpHeader = (struct tcphdr *)(payloadData + (ipHeader->ihl<<2));
		unsigned int sourcePort = ntohs(tcpHeader->source);
		unsigned int destPort = ntohs(tcpHeader->dest);

		PyObject *argList = Py_BuildValue("llIIs", sourceIP, destIP, sourcePort, destPort, "TCP");
		if(PyCallable_Check(pFunc)){
			pValue = PyObject_CallObject(pFunc, argList);
		} else {
			PyErr_Print();
		}

		Py_DECREF(argList);

		if(PyObject_IsTrue(pValue) == 1){

			printf("Accept from:%04x to:%04x From port %u to port %u\n", sourceIP, destIP, sourcePort, destPort);	
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		} else {
			printf("Drop from:%04x to:%04x From port %u to port %u\n", sourceIP, destIP, sourcePort, destPort);	
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		} 
	} else if (ipHeader->protocol == IPPROTO_UDP){
		struct udphdr *udpHeader = (struct udphdr *)(payloadData + (ipHeader->ihl<<2));
		unsigned int sourcePort = ntohs(udpHeader->source);
		unsigned int destPort = ntohs(udpHeader->dest);

		PyObject *argList = Py_BuildValue("llIIs", sourceIP, destIP, sourcePort, destPort, "UDP");
		if(PyCallable_Check(pFunc)){
			pValue = PyObject_CallObject(pFunc, argList);
		} else {
			PyErr_Print();
		}
		Py_DECREF(argList);

		if(PyObject_IsTrue(pValue) == 1){

			printf("Accept from:%04x to:%04x From port %u to port %u\n", sourceIP, destIP, sourcePort, destPort);	
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		} else {
			printf("Drop from:%04x to:%04x From port %u to port %u\n", sourceIP, destIP, sourcePort, destPort);	
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		} 
	} else {
		printf("Packet accepted: Protocol not supported.");
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	//tcpHeader = (struct tcphdr *)(payloadData + (ipHeader->ihl<<2));
	/*if(ipHeader->protocol == IPPROTO_TCP){
		printf("Accept from:%lu From port %04x to port %04x\n", ipHeader->saddr, ntohs(tcpHeader->source), ntohs(tcpHeader->dest));	
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	} else {
		printf("Drop from:%lu From port %hu to port %hu\n", ipHeader->saddr, tcpHeader->source, tcpHeader->dest);
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}*/
}

int main(int argc, char *argv[])
{
	setenv("PYTHONPATH", ".", 1);
	Py_Initialize();
	pName = PyUnicode_FromString("pythonModule");
	pModule = PyImport_Import(pName);
	pDict = PyModule_GetDict(pModule);
	pFunc = PyDict_GetItemString(pDict, "verify");
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	// para el tema del loss:   while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)

	while ((rv = recv(fd, buf, sizeof(buf), 0)))
	{
		printf("pkt received\n");
		nfq_handle_packet(h, buf, rv);
	}
	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	Py_DECREF(pModule);
	Py_DECREF(pName);
	Py_Finalize();

	exit(0);
}
