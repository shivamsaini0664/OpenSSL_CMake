#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <string>


using namespace std;

int main() {

  RSA* rsa = RSA_new();
  BIGNUM* e = BN_new();
  BN_set_word(e, RSA_F4);
  if (RSA_generate_key_ex(rsa, 2048, e, nullptr) != 1) {
    cerr << "Failed to generate RSA key pair." << endl;
    return 1;
  }
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <openssl/ecdsa.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/engine.h>
#include <openssl/sha.h>

#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

  string s;
  cin>>s;

  
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, s.c_str(), 256);
  SHA256_Final(hash, &sha256);

  std::cout << "SHA256 hash: ";
  for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    std::cout << std::hex << (int)hash[i];
  } 
  std::cout << std::endl;



  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPublicKey(bio, rsa);
  char* public_key_str;
  size_t public_key_len = BIO_get_mem_data(bio, &public_key_str);
  cout << "Public key:\n" << string(public_key_str, public_key_len) << endl;
  BIO_reset(bio);

  PEM_write_bio_RSAPrivateKey(bio, rsa, nullptr, nullptr, 0, nullptr, nullptr);
  char* private_key_str;
  size_t private_key_len = BIO_get_mem_data(bio, &private_key_str);
  cout << "Private key:\n" << string(private_key_str, private_key_len) << endl;

  RSA_free(rsa);
  BN_free(e);
  BIO_free(bio);

  return 0;
}