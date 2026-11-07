// A small command-line app gated by Carcha Seal, to try the C++ SDK against a license server:
//
//   seal_cli <server url> <product> <public key PEM file> <storage folder> activate <license key>
//   seal_cli <server url> <product> <public key PEM file> <storage folder> check
//   seal_cli <server url> <product> <public key PEM file> <storage folder> deactivate
//
// In your app, put the public key in the code instead of reading it from a file.
#include <carcha/seal.hpp>

#include <fstream>
#include <iostream>
#include <sstream>

namespace seal = carcha::seal;

static void print(const seal::State& s) {
  std::cout << "status: " << seal::to_string(s.status) << (s.offline ? " (offline)" : "") << "\n";
  if (s.message) std::cout << "message: " << *s.message << "\n";
  if (s.customer) std::cout << "customer: " << *s.customer << "\n";
  std::cout << "features:";
  for (const auto& f : s.features) std::cout << " " << f;
  std::cout << "\n";
  if (s.expires_at) std::cout << "expires: " << *s.expires_at << "\n";
  if (s.revalidate_by) std::cout << "check in by: " << *s.revalidate_by << "\n";
}

int main(int argc, char** argv) {
  if (argc < 6) {
    std::cerr << "usage: " << argv[0] << " <server url> <product> <public key PEM file> <storage folder> activate <key> | check | deactivate\n";
    return 2;
  }
  std::ifstream key_file(argv[3]);
  std::stringstream keys;
  keys << key_file.rdbuf();
  seal::Options options;
  options.server_url = argv[1];
  options.product = argv[2];
  options.public_keys = keys.str();
  options.storage_dir = argv[4];
  options.app_version = "1.0.0";
  const std::string command = argv[5];
  try {
    seal::Client client(options);
    if (command == "activate" && argc == 7) {
      print(client.activate(argv[6]));
    } else if (command == "check") {
      print(client.check());
    } else if (command == "deactivate") {
      client.deactivate();
      std::cout << "deactivated\n";
    } else {
      std::cerr << "unknown command\n";
      return 2;
    }
  } catch (const seal::LicenseError& e) {
    std::cerr << e.code() << ": " << e.what() << "\n";
    return 1;
  } catch (const std::invalid_argument& e) {
    std::cerr << e.what() << "\n";
    return 2;
  }
  return 0;
}
