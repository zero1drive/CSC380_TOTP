#include "totp.h"
#include "verifier.h"

#include <cassert>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

struct TestVector {
  uint64_t time;
  std::string expected;
};

void test_rfc6238_vectors() {
  const std::string secret = "12345678901234567890";
  const std::vector<TestVector> vectors = {
      {59ULL, "94287082"},         {1111111109ULL, "07081804"},
      {1111111111ULL, "14050471"}, {1234567890ULL, "89005924"},
      {2000000000ULL, "69279037"}, {20000000000ULL, "65353130"},
  };

  for (const auto &v : vectors) {
    std::string actual = generate_totp(secret, v.time, 30, 8);
    if (actual != v.expected) {
      std::cerr << "FAIL at time " << v.time << ": expected " << v.expected
                << ", got " << actual << "\n";
      std::exit(1);
    }
  }
  std::cout << "[PASS] All 6 RFC 6238 SHA-1 test vectors\n";
}

void test_step_and_validation() {
  const std::string secret = "12345678901234567890";

  // Same 30-second step should produce identical 6-digit codes
  std::string startOfStep = generate_totp(secret, 30);
  std::string endOfStep = generate_totp(secret, 59);
  assert(startOfStep.size() == 6);
  assert(startOfStep == endOfStep);
  assert(startOfStep != generate_totp(secret, 60));

  // Invalid inputs should throw
  bool threw = false;
  try {
    generate_totp("", 59);
  } catch (const std::invalid_argument &) {
    threw = true;
  }
  assert(threw);

  threw = false;
  try {
    generate_totp(secret, 59, 0, 6);
  } catch (const std::invalid_argument &) {
    threw = true;
  }
  assert(threw);

  threw = false;
  try {
    generate_totp(secret, 59, 30, 10);
  } catch (const std::invalid_argument &) {
    threw = true;
  }
  assert(threw);

  std::cout << "[PASS] Step boundary and input validation checks\n";
}

void test_verifier_integration() {
  const std::string secret = "12345678901234567890";
  const uint64_t serverTime = 1234567890ULL;

  std::string prevCode = generate_totp(secret, serverTime - 30);
  std::string currCode = generate_totp(secret, serverTime);
  std::string nextCode = generate_totp(secret, serverTime + 30);

  // window = 0: only current step accepted
  TotpVerifier strictVerifier(secret, /*window=*/0);
  assert(!strictVerifier.verify(prevCode, serverTime).accepted);
  assert(!strictVerifier.verify(nextCode, serverTime).accepted);
  VerifyResult r = strictVerifier.verify(currCode, serverTime);
  assert(r.accepted && r.matchedOffset == 0 && r.reason == "ok");

  // Reusing the same code should be rejected
  VerifyResult replay = strictVerifier.verify(currCode, serverTime);
  assert(!replay.accepted && replay.reason == "reused");

  // window = 1: previous, current, and next steps accepted (use reset between)
  TotpVerifier wideVerifier(secret, /*window=*/1);
  r = wideVerifier.verify(prevCode, serverTime);
  assert(r.accepted && r.matchedOffset == -1);

  wideVerifier.reset();
  r = wideVerifier.verify(nextCode, serverTime);
  assert(r.accepted && r.matchedOffset == 1);

  std::cout << "[PASS] TotpVerifier integration checks\n";
}

int main() {
  test_rfc6238_vectors();
  test_step_and_validation();
  test_verifier_integration();
  std::cout << "All generator checks passed!\n";
  return 0;
}