#include <thread>
#include "mdns_cpp/mdns.hpp"

int main() {
  mdns_cpp::mDNS mdns;
  const std::string service = "_http._tcp.local.";
  mdns.executeQuery(service);
  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  return 0;
}