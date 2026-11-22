#pragma once

#include <cstdint>
#include <string>

// Result of one verification attempt.
struct VerifyResult {
    bool accepted;        // true if the code was accepted
    int matchedOffset;    // which step matched: -1 = previous, 0 = current, +1 = next (only valid if accepted)
    std::string reason;   // "ok", "malformed", "no match", "reused", "locked"
};

// Checks TOTP codes for one user.
//
// window      0 = only the current 30s step, 1 = previous + current + next, etc.
// maxFailures consecutive wrong codes allowed before locking (0 = no limit)
//
// Also blocks reuse: once a code from time step N is accepted, any code from
// step N or earlier is rejected (RFC 6238 Section 5.2).
class TotpVerifier {
public:
    TotpVerifier(const std::string& secret,
                 int window = 1,
                 int maxFailures = 0,
                 int stepSeconds = 30,
                 int digits = 6);

    // serverTime = the server's current Unix time in seconds.
    // Experiments can pass a fake time to simulate clock offsets.
    VerifyResult verify(const std::string& code, uint64_t serverTime);

    void setWindow(int window);  // throws std::invalid_argument if window < 0
    int  failures() const { return failures_; }
    bool locked() const { return locked_; }
    void reset();  // clears reuse history, failure count, and lock (for running experiments back to back)

private:
    bool isWellFormed(const std::string& code) const;
    static bool sameCode(const std::string& a, const std::string& b);  // constant-time compare

    std::string secret_;
    int window_;
    int maxFailures_;
    int stepSeconds_;
    int digits_;

    bool     hasUsedStep_ = false;
    uint64_t lastUsedStep_ = 0;
    int      failures_ = 0;
    bool     locked_ = false;
};