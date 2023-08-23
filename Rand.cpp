#include <iostream>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <cstdlib>
using namespace std;

int main() {
  
  unsigned char rand_num[4];
  if (RAND_bytes(rand_num, sizeof(rand_num)) != 1) {
    cerr << "Failed to generate random number." << endl;
    return 1;
  }
 std::system("openssl version");
  
  cout << "Random number: ";
  for (size_t i = 0; i < sizeof(rand_num); i++) {
    cout << hex << (int)rand_num[i];
  }
  cout << dec << endl;

  return 0;
}