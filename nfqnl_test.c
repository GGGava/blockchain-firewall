// COMPILE WITH gcc -Wall -o test.o nfqnl_test.c -lnfnetlink -lnetfilter_queue -I/usr/include/python3.6m -lpython3.6m -w

//sudo iptables -A INPUT -s [IP] -j NFQUEUE --queue-num 0


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
#include <linux/icmp.h> 
#include <arpa/inet.h> 
#include <netdb.h> 
#include <time.h> 

#include <python3.6/Python.h>

PyObject *pName, *pModule, *pDict, *pVerify, *pAddress,*pValueAddress, *pValueVerify;

#define PING_PKT_S 60 
   
// Automatic port number 
#define PORT_NO 0  
  
// Automatic port number 
#define PING_SLEEP_RATE 1000000 
  
// Gives the timeout delay for receiving packets 
// in seconds 
#define RECV_TIMEOUT 1  

int sockfd;

struct ping_pkt 
{ 
    struct icmphdr hdr; 
    char msg[PING_PKT_S-sizeof(struct icmphdr)]; 
};

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

unsigned short checksum(void *b, int len) 
{    unsigned short *buf = b; 
    unsigned int sum=0; 
    unsigned short result; 
  
    for ( sum = 0; len > 1; len -= 2 ) 
        sum += *buf++; 
    if ( len == 1 ) 
        sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
} 

char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con) 
{ 
    struct hostent *host_entity; 
    char *ip=(char*)malloc(NI_MAXHOST*sizeof(char)); 
    int i; 
  
    if ((host_entity = gethostbyname(addr_host)) == NULL) 
    { 
        // No ip found for hostname 
        return NULL; 
    } 
      
    //filling up address structure 
    strcpy(ip, inet_ntoa(*(struct in_addr *) 
                          host_entity->h_addr)); 
  
    (*addr_con).sin_family = host_entity->h_addrtype; 
    (*addr_con).sin_port = htons (PORT_NO); 
    (*addr_con).sin_addr.s_addr  = *(long*)host_entity->h_addr; 
  
    return ip; 
      
} 
void set_icmp(char* source, unsigned char* payloadData){
 
    char *ip_addr, *reverse_hostname; 
    struct sockaddr_in addr_con; 
    int addrlen = sizeof(addr_con); 
    char net_buf[NI_MAXHOST]; 
  
    ip_addr = dns_lookup(source, &addr_con);

    if (!ip_addr){
    	printf("Invalid IP, can't send ICMP packet.");
    	return;
    }
    printf(ip_addr);

    int ttl_val=64, msg_count=0, i, addr_len, flag=1, msg_received_count=0; 
      
    struct ping_pkt pckt; 
    struct sockaddr_in r_addr; 
    struct timespec time_start, time_end, tfs, tfe; 
    long double rtt_msec=0, total_msec=0; 
    struct timeval tv_out; 
    tv_out.tv_sec = RECV_TIMEOUT; 
    tv_out.tv_usec = 0; 
  
    clock_gettime(CLOCK_MONOTONIC, &tfs); 
  
      
    // set socket options at ip to TTL and value to 64, 
    // change to what you want by setting ttl_val 
    if (setsockopt(sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) 
    { 
        printf("\nSetting socket options to TTL failed!\n"); 
        return; 
    } 
  
    else
    { 
        printf("\nSocket set to TTL..\n"); 
    } 

    //filling packet 
    bzero(&pckt, sizeof(pckt)); 
      
    //Type reserved
    pckt.hdr.type = 50;
    pckt.hdr.code = ICMP_PORT_UNREACH;
      
    //pckt.hdr.un.echo.sequence = msg_count++; 

    printf("Size header: %d\n", sizeof(pckt.hdr));


    struct iphdr *ipHeader = (struct iphdr *)payloadData;

    printf("1\n");

    memcpy(pckt.msg, payloadData, (ipHeader->ihl)*4+8);

    printf("2\n");
	

	if(PyCallable_Check(pAddress)){
		pValueAddress = PyObject_CallObject(pAddress, NULL);
	} else {
		printf("Coudn't get Smart Contract adress.");
		//PyErr_Print();
	}

	unsigned char temp[40], *pos = temp;
	unsigned char address[20];

	printf("3\n");

	memcpy(temp, PyUnicode_AsUTF8(pValueAddress)+2, 40);

	printf("4\n");

	for (size_t count = 0; count < sizeof address/sizeof *address; count++) {
        sscanf(pos, "%2hhx", &address[count]);
        pos += 2;
    }

    printf("5\n");
	memcpy(pckt.msg+(ipHeader->ihl)*4+8, address, 20);

    printf("6\n");


	for(int i = (ipHeader->ihl)*4+8; i < PING_PKT_S-sizeof(struct icmphdr); i++){
		if(i%4==0){
			printf("\n");
		}
		printf(" %02X ", (unsigned char)pckt.msg[i]);
	}

	printf("\n");

    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt)); 

    //send packet 
    if (sendto(sockfd, &pckt, sizeof(pckt), 0, &addr_con, sizeof(addr_con)) <= 0) 
    { 
        printf("\nPacket Sending Failed!\n"); 
        flag=0; 
    } else {
    	printf("Packet sent to: (h: %s)(%s) \n", source, ip_addr);
    }

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

	char ipStringSource[16];
	char ipStringDest[16];

    sprintf(ipStringSource, "%d.%d.%d.%d", (sourceIP >> 24) & 0xFF, (sourceIP >> 16) & 0xFF, (sourceIP >> 8) & 0xFF, (sourceIP >> 0) & 0xFF);
	sprintf(ipStringDest, "%d.%d.%d.%d", (destIP >> 24) & 0xFF, (destIP >> 16) & 0xFF, (destIP >> 8) & 0xFF, (destIP >> 0) & 0xFF);

	if(ipHeader->protocol == IPPROTO_TCP){
		struct tcphdr *tcpHeader = (struct tcphdr *)(payloadData + (ipHeader->ihl<<2));
		unsigned int sourcePort = ntohs(tcpHeader->source);
		unsigned int destPort = ntohs(tcpHeader->dest);

		PyObject *argList = Py_BuildValue("llIIs", sourceIP, destIP, sourcePort, destPort, "TCP");
		if(PyCallable_Check(pVerify)){
			pValueVerify = PyObject_CallObject(pVerify, argList);
		} else {
			PyErr_Print();
		}

		Py_DECREF(argList);

		if(PyObject_IsTrue(pValueVerify) == 1){

			printf("Accept from:%04x to:%04x From port %u to port %u\n", sourceIP, destIP, sourcePort, destPort);	
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		} else {
			set_icmp(ipStringSource, payloadData);
			printf("Drop from:%04x to:%04x From port %u to port %u\n", sourceIP, destIP, sourcePort, destPort);	
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		} 
	} else if (ipHeader->protocol == IPPROTO_UDP){
		struct udphdr *udpHeader = (struct udphdr *)(payloadData + (ipHeader->ihl<<2));
		unsigned int sourcePort = ntohs(udpHeader->source);
		unsigned int destPort = ntohs(udpHeader->dest);

		PyObject *argList = Py_BuildValue("llIIs", sourceIP, destIP, sourcePort, destPort, "UDP");
		if(PyCallable_Check(pVerify)){
			pValueVerify = PyObject_CallObject(pVerify, argList);
		} else {
			PyErr_Print();
		}
		Py_DECREF(argList);

		if(PyObject_IsTrue(pValueVerify) == 1){

			printf("Accept from:%04x to:%04x From port %u to port %u\n", sourceIP, destIP, sourcePort, destPort);	
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		} else {
			set_icmp(ipStringSource, payloadData);
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
	pVerify = PyDict_GetItemString(pDict, "verify");
	pAddress = PyDict_GetItemString(pDict, "getAddress");
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); 
    if(sockfd<0) 
    { 
        printf("\nSocket file descriptor not received!!\n"); 
        return 0; 
    } 
    else {
        printf("\nSocket file descriptor %d received\n", sockfd);
    }

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
