#include "verifier.h"
#include "totp.h"

#include <cctype>
#include <stdexcept>

TotpVerifier::TotpVerifier(const std::string& secret, int window, int maxFailures,
                           int stepSeconds, int digits)
    : secret_(secret), window_(0), maxFailures_(maxFailures),
      stepSeconds_(stepSeconds), digits_(digits) {
    setWindow(window);
}

void TotpVerifier::setWindow(int window) {
    if (window < 0) throw std::invalid_argument("Window must be non-negative");
    window_ = window;
}

void TotpVerifier::reset() {
    hasUsedStep_ = false;
    lastUsedStep_ = 0;
    failures_ = 0;
    locked_ = false;
}

bool TotpVerifier::isWellFormed(const std::string& code) const {
    if (static_cast<int>(code.size()) != digits_) return false;
    for (char c : code) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

// Compares every character even after a mismatch, so timing doesn't leak
// how many leading digits were right.
bool TotpVerifier::sameCode(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

VerifyResult TotpVerifier::verify(const std::string& code, uint64_t serverTime) {
    if (locked_) return {false, 0, "locked"};

    if (!isWellFormed(code)) return {false, 0, "malformed"};

    const int64_t currentStep = static_cast<int64_t>(serverTime / stepSeconds_);

    for (int offset = -window_; offset <= window_; ++offset) {
        const int64_t step = currentStep + offset;
        if (step < 0) continue;

        const uint64_t stepTime = static_cast<uint64_t>(step) * stepSeconds_;
        const std::string expected =
            generate_totp(secret_, stepTime, stepSeconds_, digits_);  // GENERATOR CALL

        if (sameCode(code, expected)) {
            // Reuse check: this step (or an older one) was already used.
            if (hasUsedStep_ && static_cast<uint64_t>(step) <= lastUsedStep_) {
                return {false, offset, "reused"};
            }
            hasUsedStep_ = true;
            lastUsedStep_ = static_cast<uint64_t>(step);
            failures_ = 0;
            return {true, offset, "ok"};
        }
    }

    // Wrong code: count it toward the attempt limit.
    ++failures_;
    if (maxFailures_ > 0 && failures_ >= maxFailures_) locked_ = true;
    return {false, 0, "no match"};
}
