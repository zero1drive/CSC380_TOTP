#include "totp.h"

#include <stdexcept>

#include <cryptopp/sha.h> // only SHA-1 comes from the library

#include <iomanip>
#include <sstream>
#include <vector>

// HMAC(K,M) = SHA1((K XOR opad) || SHA1((K XOR ipad) || M))
static void hmac_sha1(const std::string &key, const uint8_t *message,
                      size_t messageLen,
                      CryptoPP::byte out[CryptoPP::SHA1::DIGESTSIZE]) {
  const size_t blockSize = CryptoPP::SHA1::BLOCKSIZE; // 64 bytes
  // a key longer than one block is hashed first, then padded with zeros to 64 bytes
  std::vector<CryptoPP::byte> normalized(key.begin(), key.end());
  if (normalized.size() > blockSize) {
    CryptoPP::byte hashed[CryptoPP::SHA1::DIGESTSIZE];
    CryptoPP::SHA1().CalculateDigest(hashed, normalized.data(), normalized.size());
    normalized.assign(hashed, hashed + sizeof(hashed));
  }
  normalized.resize(blockSize, 0);
  // HMAC hashes once with the inner pad, then with the outer pad
  std::vector<CryptoPP::byte> inner(blockSize), outer(blockSize);
  for (size_t i = 0; i < blockSize; ++i) {
    inner[i] = normalized[i] ^ 0x36;
    outer[i] = normalized[i] ^ 0x5c;
  }
  // inner hash = SHA1(inner pad || message)
  CryptoPP::byte innerHash[CryptoPP::SHA1::DIGESTSIZE];
  CryptoPP::SHA1 innerSha;
  innerSha.Update(inner.data(), blockSize);
  innerSha.Update(message, messageLen);
  innerSha.Final(innerHash);
  // result = SHA1(outer pad || inner hash)
  CryptoPP::SHA1 outerSha;
  outerSha.Update(outer.data(), blockSize);
  outerSha.Update(innerHash, sizeof(innerHash));
  outerSha.Final(out);
}

std::string generate_totp(const std::string &secret, uint64_t unixTime,
                          int stepSeconds, int digits) {
  if (secret.empty()) {
    throw std::invalid_argument("Secret key cannot be empty");
  }
  if (stepSeconds <= 0) {
    throw std::invalid_argument("Time step must be positive");
  }
  if (digits < 1 || digits > 9) {
    throw std::invalid_argument("Digits must be between 1 and 9");
  }

  // count how many time steps have passed since 1970
  uint64_t counter = unixTime / static_cast<uint64_t>(stepSeconds);

  // store the counter as 8 bytes, most significant byte first
  uint8_t counterBytes[8];
  for (int i = 7; i >= 0; --i) {
    counterBytes[i] = static_cast<uint8_t>(counter & 0xFF);
    counter >>= 8;
  }

  // mix the secret and counter with our own HMAC-SHA-1 (20 bytes)
  CryptoPP::byte digest[CryptoPP::SHA1::DIGESTSIZE];
  hmac_sha1(secret, counterBytes, sizeof(counterBytes), digest);

  // dynamic truncation: the last 4 bits pick where to read 4 bytes from
  int offset = digest[CryptoPP::SHA1::DIGESTSIZE - 1] & 0x0F;
  // drop the top bit so the number is never negative
  uint32_t binary = ((static_cast<uint32_t>(digest[offset]) & 0x7F) << 24) |
                    ((static_cast<uint32_t>(digest[offset + 1]) & 0xFF) << 16) |
                    ((static_cast<uint32_t>(digest[offset + 2]) & 0xFF) << 8) |
                    (static_cast<uint32_t>(digest[offset + 3]) & 0xFF);

  // keep only the last `digits` digits
  uint32_t mod = 1;
  for (int i = 0; i < digits; ++i) {
    mod *= 10;
  }
  uint32_t otp = binary % mod;

  // add leading zeros so the code always has `digits` characters
  std::ostringstream oss;
  oss << std::setw(digits) << std::setfill('0') << otp;
  return oss.str();
}
