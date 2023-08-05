#include "mdns.h"

#include <algorithm> // std::min

#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cstdio> // printf

constexpr int IFF_UP 			= 0x1;		// interface is up
constexpr int IFF_LOOPBACK 		= 0x8;      // is a loopback net 
constexpr int IFF_POINTOPOINT 	= 0x10;     // interface is point-to-point link 
constexpr int IFF_MULTICAST 	= 0x1000;   // supports multicast

/**
 * @brief Perform reverse DNS lookup. It looks up the IP address in the struct sockaddr and 
 * tries to resolve it to a hostname (domain name). Similarly, it attempts to map the port number to a 
 * service name (e.g., "http", "ssh", "ftp") if available.
 * 
 * @param buffer buffer for the result
 * @param capacity size of the buffer 
 * @param addr struct that contains IP address
 * @param addr_len size the addr struct
 * @return mdns_string_t where .str points to buffer and .length is result len 
 */
static mdns_string_t ipv4AddrToString(char* buffer, size_t capacity, const struct sockaddr_in* addr, size_t addr_len) 
{
	char host[NI_MAXHOST] = {0};
	char service[NI_MAXSERV] = {0};

	// The getnameinfo() function is used to perform a reverse DNS lookup. 
	// It is used to convert an IP address and port number into a corresponding hostname and service name.
	//
	// When getnameinfo() is called, it looks up the IP address in the struct sockaddr and 
	// tries to resolve it to a hostname (domain name). Similarly, it attempts to map the port number to a 
	// service name (e.g., "http", "ssh", "ftp") if available.
	//
	// The function takes the following parameters:
	// const struct sockaddr *sa: A pointer to a struct sockaddr that contains the IP address and port number you want to resolve.
	// socklen_t salen: The size of the struct sockaddr.
	// char *host: A pointer to a buffer where the resulting hostname will be stored.
	// size_t hostlen: The size of the buffer pointed to by host.
	// char *serv: A pointer to a buffer where the resulting service name will be stored.
	// size_t servlen: The size of the buffer pointed to by serv.
	// int flags: Optional flags that modify the behavior of the function.
	int ret = getnameinfo((const struct sockaddr*)addr, static_cast<socklen_t>(addr_len), host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
	
	int len = 0;
	if (ret == 0) 
	{
		if (addr->sin_port != 0)
		{
			len = snprintf(buffer, capacity, "%s:%s", host, service);
		}
		else
		{
			len = snprintf(buffer, capacity, "%s", host);
		}
	}

    // Ensure that the resulting string fits within the buffer's capacity.
    len = std::min(len, static_cast<int>(capacity - 1));
	
	mdns_string_t str;
	str.str = buffer;
	str.length = len;

	return str;
}

/**
 * @brief Perform reverse DNS lookup. It looks up the IP address in the struct sockaddr and 
 * tries to resolve it to a hostname (domain name). Similarly, it attempts to map the port number to a 
 * service name (e.g., "http", "ssh", "ftp") if available.
 * 
 * @param buffer buffer for the result
 * @param capacity size of the buffer 
 * @param addr struct that contains IP address
 * @param addr_len size the addr struct
 * @return mdns_string_t where .str points to buffer and .length is result len 
 */
static mdns_string_t ipAddrToString(char* buffer, size_t capacity, const struct sockaddr* addr, size_t addr_len) 
{
	return ipv4AddrToString(buffer, capacity, (const struct sockaddr_in*)addr, addr_len);
}

/**
 * @brief Callback handling parsing answers to queries sent
 */
static int query_callback(int sock, const struct sockaddr* from, size_t addr_len, mdns_entry_type_t entry,
               uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
               size_t size, size_t name_offset, size_t name_length, size_t record_offset,
               size_t record_length, void* user_data) 
{
	(void)sizeof(sock);
	(void)sizeof(query_id);
	(void)sizeof(name_length);
	(void)sizeof(user_data);

	char addr_buffer[64];
	char entry_buffer[256];
	char name_buffer[256];

	printf("response received");

	mdns_string_t from_addr_str = ipAddrToString(addr_buffer, sizeof(addr_buffer), from, addr_len);

	const char* entry_type = (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" : ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
	
	mdns_string_t entry_str = mdns_string_extract(data, size, &name_offset, entry_buffer, sizeof(entry_buffer));
	
 	if (rtype == MDNS_RECORDTYPE_A) 
	{
		struct sockaddr_in addr;
		mdns_record_parse_a(data, size, record_offset, record_length, &addr);
		mdns_string_t addrstr = ipv4AddrToString(name_buffer, sizeof(name_buffer), &addr, sizeof(addr));

		printf("%.*s : %s %.*s A %.*s\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(addrstr));
	} 
	else 
	{
		printf("%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n",
		       MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), rtype,
		       rclass, ttl, (int)record_length);
	}
	return 0;
}

// Open sockets for sending one-shot multicast queries from an ephemeral port
static int openSockets(int* sockets, int max_sockets, int port) 
{
	// When sending, each socket can only send to one network interface
	// Thus we need to open one socket for each interface and address family
	int num_sockets = 0;

	struct ifaddrs* ifaddr = 0;
	struct ifaddrs* ifa = 0;

 	struct sockaddr_in service_address_ipv4;

	if (getifaddrs(&ifaddr) < 0)
	{
		printf("Unable to get interface addresses\n");
	}

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
					mdns_string_t addr = ipv4AddrToString(buffer, sizeof(buffer), saddr,
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
	int num_sockets = openSockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
	
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
		if (query[iq].type == MDNS_RECORDTYPE_A)
			record_name = "A";

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

int main(int argc, const char* const* argv) 
{
	int mode = 0;
	const char* service = "Juhans-MacBook-Pro.local";
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