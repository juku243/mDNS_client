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
 * @brief Get IP address (host) and port (service) from the sockaddr_in struct, and return it in format host:port.
 * 
 * @param buffer buffer for the result string that contains host:port
 * @param capacity size of the buffer 
 * @param addr struct that contains IP address (host) and port (service)
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
	// When you pass the combination of NI_NUMERICSERV and NI_NUMERICHOST flags to the getnameinfo() function, 
	// it instructs the function to perform a numeric (non-reverse) lookup for both the service (port number) and 
	// host (IP address) parts of the struct sockaddr provided in the input.
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
static int queryCallback(int sock, const struct sockaddr* from, size_t addr_len, mdns_entry_type_t entry,
               uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
               size_t size, size_t name_offset, size_t name_length, size_t record_offset,
               size_t record_length, void* user_data) 
{
	(void)sizeof(sock);
	(void)sizeof(query_id);
	(void)sizeof(name_length);

	char addr_buf[64];		// buffer to store host:port string that send the response message
	char entry_buf[256];	// buffer to store the hostname that was queried
	char name_buf[256];		// buffer to store the query answer (IP address)

	printf("response received: ");

	// get IP and port of the device that send the response message
	mdns_string_t from_addr_str = ipAddrToString(addr_buf, sizeof(addr_buf), from, addr_len);

	// get the resource record type 
	const char* entry_type = (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" : ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
	
	// get the hostname that was queried
	mdns_string_t entry_str = mdns_string_extract(data, size, &name_offset, entry_buf, sizeof(entry_buf));
	
	// if resource record is a answer
 	if(rtype == MDNS_RECORDTYPE_A) 
	{
		struct sockaddr_in addr;

		// parse answer resource record and store it to the addr struct
		mdns_record_parse_a(data, size, record_offset, record_length, &addr);

		// get IP addr (answer) from the addr struct 
		mdns_string_t addrstr = ipv4AddrToString(name_buf, sizeof(name_buf), &addr, sizeof(addr));

		// store answer to the user_data (buffer), just for the demo purposes
		char* char_data = (char*)user_data;
		strcat(char_data, addrstr.str);

		// print response 
		printf("%.*s : %s %.*s A %.*s\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(addrstr));
	} 
	else 
	{
		// for the other resource records print just details
		printf("%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n",
		       MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), rtype,
		       rclass, ttl, (int)record_length);
	}
	return 0;
}

/**
 * @brief Open socket for the each interface that is open, supports multicast, address is IPv4, is not loopback 
 * and is not point-to-point interface.
 * 
 * @param sockets buffer to store the sockets
 * @param max_sockets maximum number of sockets that will be opened
 * @param port that is used by the sockets, if 0 random port will be assigned
 * 
 * @return number of sockets opened 
 */
static int openSockets(int* sockets, int max_sockets, int port) 
{
	// When sending, each socket can only send to one network interface
	// Thus we need to open one socket for each interface and address family
	int num_sockets = 0;

	struct ifaddrs* ifaddr = 0;
	struct ifaddrs* ifa = 0;

 	struct sockaddr_in service_address_ipv4;

	// The getifaddrs() function is used to retrieve information about the network interfaces 
	// available on the system. It allows you to obtain a linked list of network interface structures, 
	// each containing details about a specific network interface, such as its name, address, netmask, 
	// and other configuration information.
	if(getifaddrs(&ifaddr) < 0)
	{
		printf("Unable to get interface addresses\n");
		return 0;
	}

	int first_ipv4 = 1;
	// loop through all the interfaces
	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) 
  	{
		// if network interface does not have network address
		if (!ifa->ifa_addr)
			continue;
		// if network interface is not up or does not support multicast communication
		// Multicast allows data to be sent from one sender to multiple receivers, 
		// enabling efficient group communication.
		if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST))
			continue;
		// if network interface is loopback interface (used for communication within the local host itself)
		// The loopback interface is a virtual network interface used for communication within the local host 
		// itself. It is often referred to by the IP address "127.0.0.1". Packets sent to the loopback address are 
		// looped back and delivered to the receiving application on the same host. The loopback interface is used 
		// for testing network software and ensuring network services work correctly 
		// even without an active network connection.
		//
		// or nwtwork interface is point-to-point interface. A point-to-point interface is a direct link between 
		// two network nodes, typically used for point-to-point communication, such as in a VPN (Virtual Private Network) 
		// or when connecting to another device directly. In a point-to-point interface, each endpoint can directly 
		// communicate with the other without going through a network switch or router.
		if ((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT))
			continue;

		// if address family is IPv4 
		if (ifa->ifa_addr->sa_family == AF_INET) 
		{
			struct sockaddr_in* saddr = (struct sockaddr_in*)ifa->ifa_addr;
			
			// if address is not loopback address
			// Loopback IP address for IPv4, is 127.0.0.1. The loopback address is used to establish 
			// communication within the same host (localhost).
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
					// open socket for the interface
					saddr->sin_port = htons(port);
					int sock = mdns_socket_open_ipv4(saddr);
					if (sock >= 0) 
					{
						sockets[num_sockets++] = sock;
						log_addr = 1;
					} 
					else 
					{
						log_addr = 0;
					}
				}
				if (log_addr) 
				{
					// if socket open, print out the interface IP address
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

/**
 * @brief Send mDNS query
 * 
 * @param query list of mDNS query
 * @param count number of mDNS queries on the list
 * 
 * @return int 0 if queries send sucessfully, -1 otherwise
 */
static int sendQuery(mdns_query_t* query, size_t count) 
{
	int sockets[32];
	int query_id[32];
	int num_sockets = openSockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
	
	if (num_sockets <= 0) 
	{
		printf("Failed to open any client sockets\n");
		return -1;
	}
	printf("Opened %d socket%s for mDNS query\n", num_sockets, (num_sockets > 1) ? "s" : "");

	size_t capacity = 2048;
	char* buffer[capacity];
	char user_data[256] = {0}; // buffer to pass to the queryCallback

	printf("Sending mDNS query");
	for (size_t iq = 0; iq < count; ++iq) 
	{
		const char* record_name = "A";
		if (query[iq].type == MDNS_RECORDTYPE_A)
		{
			record_name = "A";
		}

		printf(" : %s %s", query[iq].name, record_name);
	}
	printf("\n");

	// loop through open sockets
	for (int isock = 0; isock < num_sockets; ++isock) 
	{
		query_id[isock] = mdns_multiquery_send(sockets[isock], query, count, buffer, capacity, 0);

		if (query_id[isock] < 0)
		{
			printf("Failed to send mDNS query: %s\n", strerror(errno));
		}
	}

	// Loop for socket TTL seconds or as long as we get replies
	int res;
	printf("Reading mDNS query replies\n");
	int records = 0;
	do {
		struct timeval timeout;
		timeout.tv_sec = 2; // set TTL for the socket 10s
		timeout.tv_usec = 0;

		int nfds = 0;

		// This declares a file descriptor set readfs, which is used to specify 
		// the sockets that will be monitored for readability.
		fd_set readfs;

		FD_ZERO(&readfs); // Initializes the file descriptor set readfs to empty.

		// This loop iterates over an array of num_sockets containing socket descriptors,
		// and adds them to the readfs descriptior so that they can be monitored for the readibility
		for (int isock = 0; isock < num_sockets; ++isock) 
		{
			if (sockets[isock] >= nfds)
			{
				nfds = sockets[isock] + 1;
			}
			// This adds the current socket descriptor to the file descriptor set readfs. 
			// i.e. socket will be monitored for readability
			FD_SET(sockets[isock], &readfs);
		}

		// This is the select() call, which blocks until there is data available for reading on any 
		// of the sockets in the readfs set or until the specified timeout of 10 seconds elapses. 
		// The result of the select() call is stored in the variable res.
		res = select(nfds, &readfs, 0, 0, &timeout);

		// if response is received from any of the interfaces (sockets)
		if (res > 0) 
		{
			// loop through the sockets
			for (int isock = 0; isock < num_sockets; ++isock) 
			{
				// if data is available to read (i.e FD is set)
				if (FD_ISSET(sockets[isock], &readfs)) 
				{
					// get response and call the callback
					size_t rec = mdns_query_recv(sockets[isock], buffer, capacity, queryCallback,
					                             user_data, query_id[isock]);
					if (rec > 0)
					{
						records += rec;
					}

					printf("Query answer is: %s\n", user_data);
				}
				// This adds the current socket descriptor to the file descriptor set readfs. 
				// i.e. socket will be monitored for readability again
				FD_SET(sockets[isock], &readfs);
			}
		}
	} while (res > 0);

	printf("Read %d records\n", records);

	for (int isock = 0; isock < num_sockets; ++isock)
	{
		mdns_socket_close(sockets[isock]);
	}
	printf("Closed socket%s\n", (num_sockets > 1) ? "s" : "");

	return 0;
}

int main() 
{
	const char* hostname = "Juhans-MacBook-Pro.local";
	mdns_query_t query[1];
	size_t query_count = 0;

	query[query_count].name = hostname;			 // hostname that IP address we are quering
	query[query_count].type = MDNS_RECORDTYPE_A; // query IPv4 address
	query[query_count].length = strlen(query[query_count].name);
	++query_count;

	sendQuery(query, query_count);

	return 0;
}