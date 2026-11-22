#include "totp.h"

#include <stdexcept>

#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

#include <iomanip>
#include <sstream>

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

  // Compute the 64-bit time step counter
  uint64_t counter = unixTime / static_cast<uint64_t>(stepSeconds);

  // Encode counter as 8 big-endian bytes
  uint8_t counterBytes[8];
  for (int i = 7; i >= 0; --i) {
    counterBytes[i] = static_cast<uint8_t>(counter & 0xFF);
    counter >>= 8;
  }

  // Compute HMAC-SHA-1 digest (20 bytes)
  CryptoPP::byte digest[CryptoPP::SHA1::DIGESTSIZE];
  CryptoPP::HMAC<CryptoPP::SHA1> hmac(
      reinterpret_cast<const CryptoPP::byte *>(secret.data()), secret.size());
  hmac.CalculateDigest(digest, counterBytes, sizeof(counterBytes));

  // Step 4: Dynamic truncation (RFC 4226 / 6238)
  int offset = digest[CryptoPP::SHA1::DIGESTSIZE - 1] & 0x0F;
  uint32_t binary = ((static_cast<uint32_t>(digest[offset]) & 0x7F) << 24) |
                    ((static_cast<uint32_t>(digest[offset + 1]) & 0xFF) << 16) |
                    ((static_cast<uint32_t>(digest[offset + 2]) & 0xFF) << 8) |
                    (static_cast<uint32_t>(digest[offset + 3]) & 0xFF);

  // Step 5: Reduce to requested number of digits and zero-pad
  uint32_t mod = 1;
  for (int i = 0; i < digits; ++i) {
    mod *= 10;
  }
  uint32_t otp = binary % mod;

  std::ostringstream oss;
  oss << std::setw(digits) << std::setfill('0') << otp;
  return oss.str();
}
