// One Client, operations from several threads: each operation's request and answer stay together, so every call
// succeeds. The transport is slow, so without the Client's lock a second check() would start while the first is
// waiting for its answer, and the first would then fail with "no_request".
// Usage: threads <folder> (license.dat is written there)
#include <carcha/seal.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace seal = carcha::seal;

// Any Ed25519 key: the saved lease below does not verify, so check() ends offline as "invalid", without throwing.
static const char* KEY = "MCowBQYDK2VwAyEALiAdmTkGG9jtE74LHZzjfNugnNT9bIvVBRm0onTDGgQ=";

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: threads <folder>\n";
    return 2;
  }
  const std::filesystem::path dir = argv[1];
  std::filesystem::remove_all(dir);
  std::filesystem::create_directories(dir);
  std::ofstream(dir / "license.dat") << R"({"licenseKey":"LK-A","token":"x.y.z","lastSeen":1})";

  std::atomic<int> in_flight{0}, most_in_flight{0}, requests{0};
  seal::Options o;
  o.product = "threads";
  o.server_url = "https://licenses.example.com";
  o.public_keys = KEY;
  o.storage_dir = dir.string();
  o.machine_id = "linux:threads";
  o.hardware = false;
  o.transport = [&](const seal::HttpRequest&) {
    const int now = ++in_flight;
    int seen = most_in_flight.load();
    while (now > seen && !most_in_flight.compare_exchange_weak(seen, now)) {
    }
    ++requests;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    --in_flight;
    return seal::HttpResponse{0, ""};  // no answer: the saved lease decides
  };
  seal::Client client(o);

  std::atomic<int> failed{0};
  std::vector<std::thread> threads;
  for (int i = 0; i < 4; ++i) {
    threads.emplace_back([&] {
      try {
        if (client.check().status != seal::Status::Invalid) ++failed;
      } catch (const std::exception& e) {
        std::cerr << "check() threw: " << e.what() << "\n";
        ++failed;
      }
    });
  }
  for (auto& t : threads) t.join();

  if (failed != 0 || requests != 4 || most_in_flight != 1) {
    std::cerr << "FAIL: failed=" << failed << " requests=" << requests << " most in flight=" << most_in_flight << "\n";
    return 1;
  }
  std::cout << "OK: 4 checks from 4 threads, one request at a time\n";
  return 0;
}
