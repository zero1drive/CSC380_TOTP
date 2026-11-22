// Experiment 1: acceptance window vs. clock offset
//
// The server checks a code at a fixed serverTime. The client's clock is off by
// `clock_offset_s` seconds, so the client generates its code at
// serverTime + clock_offset_s. We test window = 0 (current step only) and
// window = 1 (previous, current, next) at several positions inside the
// server's 30-second step, and record whether the legitimate code is accepted
// and how many distinct codes the verifier would accept at that moment.
//
// Usage: ./experiments [output.csv]     (default: results.csv)

#include "totp.h"
#include "verifier.h"

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

const std::string kSecret = "12345678901234567890";  // RFC 6238 SHA-1 test key
const int kStep = 30;
const uint64_t kBaseStep = 41152263;  // step containing t = 1234567890 (fixed for reproducibility)

const std::vector<int> kWindows = {0, 1};
const std::vector<int> kPositions = {0, 5, 10, 15, 20, 25, 29};
const int kMinOffset = -90;
const int kMaxOffset = 90;
const int kOffsetStride = 5;

// Number of distinct codes the verifier accepts at serverTime with this window.
int distinctValidCodes(uint64_t serverTime, int window) {
    const int64_t current = static_cast<int64_t>(serverTime / kStep);
    std::set<std::string> codes;
    for (int k = -window; k <= window; ++k) {
        const int64_t step = current + k;
        if (step < 0) continue;
        codes.insert(generate_totp(kSecret, static_cast<uint64_t>(step) * kStep, kStep));
    }
    return static_cast<int>(codes.size());
}

}  // namespace

int main(int argc, char* argv[]) {
    const std::string outPath = argc > 1 ? argv[1] : "results.csv";
    std::ofstream out(outPath);
    if (!out) {
        std::cerr << "Cannot open " << outPath << " for writing\n";
        return 1;
    }

    out << "window,position_in_step,clock_offset_s,accepted,matched_offset,reason,"
           "distinct_valid_codes\n";

    // window -> offset -> (accepted count, total count), for the stdout summary
    std::map<int, std::map<int, std::pair<int, int>>> summary;
    int rows = 0;

    for (int window : kWindows) {
        for (int pos : kPositions) {
            const uint64_t serverTime = kBaseStep * kStep + pos;
            const int distinct = distinctValidCodes(serverTime, window);

            for (int offset = kMinOffset; offset <= kMaxOffset; offset += kOffsetStride) {
                const uint64_t clientTime = static_cast<uint64_t>(
                    static_cast<int64_t>(serverTime) + offset);
                const std::string code = generate_totp(kSecret, clientTime, kStep);

                // Fresh verifier per trial so reuse blocking doesn't affect results.
                TotpVerifier verifier(kSecret, window);
                const VerifyResult r = verifier.verify(code, serverTime);

                out << window << ',' << pos << ',' << offset << ','
                    << (r.accepted ? 1 : 0) << ','
                    << (r.accepted ? std::to_string(r.matchedOffset) : "") << ','
                    << r.reason << ',' << distinct << '\n';

                auto& cell = summary[window][offset];
                cell.first += r.accepted ? 1 : 0;
                cell.second += 1;
                ++rows;
            }
        }
    }

    std::cout << "Wrote " << rows << " rows to " << outPath << "\n\n";
    std::cout << "Acceptance rate of a legitimate code by clock offset\n"
              << "(averaged over positions " ;
    for (size_t i = 0; i < kPositions.size(); ++i) {
        std::cout << kPositions[i] << (i + 1 < kPositions.size() ? "," : "");
    }
    std::cout << " s into the 30 s step)\n\n";

    std::cout << std::setw(10) << "offset_s";
    for (int w : kWindows) std::cout << std::setw(12) << ("window=" + std::to_string(w));
    std::cout << '\n';
    for (int offset = kMinOffset; offset <= kMaxOffset; offset += kOffsetStride) {
        std::cout << std::setw(10) << offset;
        for (int w : kWindows) {
            const auto& c = summary[w][offset];
            std::cout << std::setw(11) << std::fixed << std::setprecision(0)
                      << (100.0 * c.first / c.second) << '%';
        }
        std::cout << '\n';
    }

    std::cout << "\nDistinct codes accepted at any moment: ";
    for (int w : kWindows) {
        std::cout << "window=" << w << " -> "
                  << distinctValidCodes(kBaseStep * kStep, w) << "  ";
    }
    std::cout << '\n';
    return 0;
}
