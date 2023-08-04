#include "mdns.h"

#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cstdio> // printf

#define IFF_UP          0x1             /* interface is up */
#define IFF_BROADCAST   0x2             /* broadcast address valid */
#define IFF_DEBUG       0x4             /* turn on debugging */
#define IFF_LOOPBACK    0x8             /* is a loopback net */
#define IFF_POINTOPOINT 0x10            /* interface is point-to-point link */
#define IFF_NOTRAILERS  0x20            /* obsolete: avoid use of trailers */
#define IFF_RUNNING     0x40            /* resources allocated */
#define IFF_NOARP       0x80            /* no address resolution protocol */
#define IFF_PROMISC     0x100           /* receive all packets */
#define IFF_ALLMULTI    0x200           /* receive all multicast packets */
#define IFF_OACTIVE     0x400           /* transmission in progress */
#define IFF_SIMPLEX     0x800           /* can't hear own transmissions */
#define IFF_LINK0       0x1000          /* per link layer defined bit */
#define IFF_LINK1       0x2000          /* per link layer defined bit */
#define IFF_LINK2       0x4000          /* per link layer defined bit */
#define IFF_ALTPHYS     IFF_LINK2       /* use alternate physical connection */
#define IFF_MULTICAST   0x8000          /* supports multicast */

static char addrbuffer[64];
static char entrybuffer[256];
static char namebuffer[256];
static char sendbuffer[1024];
static mdns_record_txt_t txtbuffer[128];

static struct sockaddr_in service_address_ipv4;

static mdns_string_t ipv4_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in* addr, size_t addrlen) 
{
	char host[NI_MAXHOST] = {0};
	char service[NI_MAXSERV] = {0};
	int ret = getnameinfo((const struct sockaddr*)addr, (socklen_t)addrlen, host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
	int len = 0;
	
  if (ret == 0) 
  {
		if (addr->sin_port != 0)
			len = snprintf(buffer, capacity, "%s:%s", host, service);
		else
			len = snprintf(buffer, capacity, "%s", host);
	}

	if (len >= (int)capacity)
		len = (int)capacity - 1;
    
	mdns_string_t str;
	str.str = buffer;
	str.length = len;
	return str;
}

static mdns_string_t ip_address_to_string(char* buffer, size_t capacity, const struct sockaddr* addr, size_t addrlen) 
{
	return ipv4_address_to_string(buffer, capacity, (const struct sockaddr_in*)addr, addrlen);
}

// Callback handling parsing answers to queries sent
static int query_callback(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
               uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
               size_t size, size_t name_offset, size_t name_length, size_t record_offset,
               size_t record_length, void* user_data) {
	(void)sizeof(sock);
	(void)sizeof(query_id);
	(void)sizeof(name_length);
	(void)sizeof(user_data);

	printf("response received");

	mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);

	const char* entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" : ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
	
	mdns_string_t entrystr = mdns_string_extract(data, size, &name_offset, entrybuffer, sizeof(entrybuffer));
	
	if (rtype == MDNS_RECORDTYPE_PTR) 
	{
		mdns_string_t namestr = mdns_record_parse_ptr(data, size, record_offset, record_length,
		                                              namebuffer, sizeof(namebuffer));
		printf("%.*s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr),
		       MDNS_STRING_FORMAT(namestr), rclass, ttl, (int)record_length);
	} 
	else if (rtype == MDNS_RECORDTYPE_SRV) 
	{
		mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length,
		                                              namebuffer, sizeof(namebuffer));
		printf("%.*s : %s %.*s SRV %.*s priority %d weight %d port %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr),
		       MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
	} 
	else if (rtype == MDNS_RECORDTYPE_A) 
	{
		struct sockaddr_in addr;
		mdns_record_parse_a(data, size, record_offset, record_length, &addr);
		mdns_string_t addrstr =
		    ipv4_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
		printf("%.*s : %s %.*s A %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(addrstr));
	} 
	else if (rtype == MDNS_RECORDTYPE_TXT) 
	{
		size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txtbuffer,
		                                      sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
		for (size_t itxt = 0; itxt < parsed; ++itxt) {
			if (txtbuffer[itxt].value.length) {
				printf("%.*s : %s %.*s TXT %.*s = %.*s\n", MDNS_STRING_FORMAT(fromaddrstr),
				       entrytype, MDNS_STRING_FORMAT(entrystr),
				       MDNS_STRING_FORMAT(txtbuffer[itxt].key),
				       MDNS_STRING_FORMAT(txtbuffer[itxt].value));
			} else {
				printf("%.*s : %s %.*s TXT %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
				       MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(txtbuffer[itxt].key));
			}
		}
	} 
	else 
	{
		printf("%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr), rtype,
		       rclass, ttl, (int)record_length);
	}
	return 0;
}

// Open sockets for sending one-shot multicast queries from an ephemeral port
static int open_client_sockets(int* sockets, int max_sockets, int port) 
{
	// When sending, each socket can only send to one network interface
	// Thus we need to open one socket for each interface and address family
	int num_sockets = 0;

	struct ifaddrs* ifaddr = 0;
	struct ifaddrs* ifa = 0;

	if (getifaddrs(&ifaddr) < 0)
		printf("Unable to get interface addresses\n");

	int first_ipv4 = 1;
	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) 
  	{
		if (!ifa->ifa_addr)
			continue;
		if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST))
			continue;
		if ((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT))
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) 
		{
			struct sockaddr_in* saddr = (struct sockaddr_in*)ifa->ifa_addr;
			
			if (saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) 
			{
				int log_addr = 0;
				if (first_ipv4) 
				{
					service_address_ipv4 = *saddr;
					first_ipv4 = 0;
					log_addr = 1;
				}
				
				if (num_sockets < max_sockets) 
				{
					saddr->sin_port = htons(port);
					int sock = mdns_socket_open_ipv4(saddr);
					if (sock >= 0) {
						sockets[num_sockets++] = sock;
						log_addr = 1;
					} else {
						log_addr = 0;
					}
				}
				if (log_addr) 
				{
					char buffer[128];
					mdns_string_t addr = ipv4_address_to_string(buffer, sizeof(buffer), saddr,
					                                            sizeof(struct sockaddr_in));
					printf("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr));
				}
			}
		} 
  }

	freeifaddrs(ifaddr);

	return num_sockets;
}

// Send a mDNS query
static int send_mdns_query(mdns_query_t* query, size_t count) 
{
	int sockets[32];
	int query_id[32];
	int num_sockets = open_client_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
	
	if (num_sockets <= 0) 
	{
		printf("Failed to open any client sockets\n");
		return -1;
	}
	printf("Opened %d socket%s for mDNS query\n", num_sockets, num_sockets ? "s" : "");

	size_t capacity = 2048;
	char* buffer[capacity];
	void* user_data = 0;

	printf("Sending mDNS query");
	for (size_t iq = 0; iq < count; ++iq) 
	{
		const char* record_name = "PTR";
		if (query[iq].type == MDNS_RECORDTYPE_SRV)
			record_name = "SRV";
		else if (query[iq].type == MDNS_RECORDTYPE_A)
			record_name = "A";
		else if (query[iq].type == MDNS_RECORDTYPE_AAAA)
			record_name = "AAAA";
		else
			query[iq].type = MDNS_RECORDTYPE_PTR;
		printf(" : %s %s", query[iq].name, record_name);
	}
	printf("\n");
	for (int isock = 0; isock < num_sockets; ++isock) 
	{
		query_id[isock] =
		    mdns_multiquery_send(sockets[isock], query, count, buffer, capacity, 0);
		if (query_id[isock] < 0)
			printf("Failed to send mDNS query: %s\n", strerror(errno));
	}

	// This is a simple implementation that loops for 5 seconds or as long as we get replies
	int res;
	printf("Reading mDNS query replies\n");
	int records = 0;
	do {
		struct timeval timeout;
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;

		int nfds = 0;
		fd_set readfs;
		FD_ZERO(&readfs);
		for (int isock = 0; isock < num_sockets; ++isock) {
			if (sockets[isock] >= nfds)
				nfds = sockets[isock] + 1;
			FD_SET(sockets[isock], &readfs);
		}

		res = select(nfds, &readfs, 0, 0, &timeout);
		if (res > 0) {
			for (int isock = 0; isock < num_sockets; ++isock) {
				if (FD_ISSET(sockets[isock], &readfs)) {
					size_t rec = mdns_query_recv(sockets[isock], buffer, capacity, query_callback,
					                             user_data, query_id[isock]);
					if (rec > 0)
						records += rec;
				}
				FD_SET(sockets[isock], &readfs);
			}
		}
	} while (res > 0);

	printf("Read %d records\n", records);

	for (int isock = 0; isock < num_sockets; ++isock)
		mdns_socket_close(sockets[isock]);
	printf("Closed socket%s\n", num_sockets ? "s" : "");

	return 0;
}

int
main(int argc, const char* const* argv) 
{
	int mode = 0;
	const char* service = "raspberrypi.local";
	mdns_query_t query[16];
	size_t query_count = 0;

	// Each query is either a service name, or a pair of record type and a service name
	// For example:
	//  mdns --query _foo._tcp.local.
	//  mdns --query SRV myhost._foo._tcp.local.
	//  mdns --query A myhost._tcp.local. _service._tcp.local.
	mode = 1;

	query[query_count].name = service;
	query[query_count].type = MDNS_RECORDTYPE_A;
	

	query[query_count].length = strlen(query[query_count].name);
	++query_count;


	int ret;
	if (mode == 1)
		ret = send_mdns_query(query, query_count);

	return 0;
}