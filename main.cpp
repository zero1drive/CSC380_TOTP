
#include "totp.h"
#include "verifier.h"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>

// Get the current Unix time in seconds.
uint64_t getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()
    );
    return static_cast<uint64_t>(seconds.count());
}

int main() {
    const std::string secret = "CSC380-TOTP-demo-secret";

    const int stepSeconds = 30;
    const int digits = 6;

    int window = 0;
    int64_t clockOffset = 0;

    // Allow up to 5 consecutive incorrect attempts.
    TotpVerifier verifier(secret, window, 5, stepSeconds, digits);

    int choice;

    while (true) {
        std::cout << "\n====================================\n";
        std::cout << "       TOTP AUTHENTICATION DEMO\n";
        std::cout << "====================================\n";
        std::cout << "Current acceptance window: " << window << "\n";
        std::cout << "Device clock offset: " << clockOffset << " seconds\n\n";

        std::cout << "1. Generate TOTP code\n";
        std::cout << "2. Verify TOTP code\n";
        std::cout << "3. Change acceptance window\n";
        std::cout << "4. Set device clock offset\n";
        std::cout << "5. Exit\n";

        std::cout << "\nChoose an option: ";

        if (!(std::cin >> choice)) {
            std::cout << "Invalid input. Exiting.\n";
            break;
        }

        if (choice == 5) {
            std::cout << "Exiting TOTP demo.\n";
            break;
        }

        if (choice == 1) {
            uint64_t serverTime = getCurrentTime();

            int64_t deviceTime =
                static_cast<int64_t>(serverTime) + clockOffset;

            if (deviceTime < 0) {
                std::cout << "Invalid device time.\n";
                continue;
            }

            std::string code = generate_totp(
                secret,
                static_cast<uint64_t>(deviceTime),
                stepSeconds,
                digits
            );

            std::cout << "\nGenerated TOTP code: " << code << "\n";
            std::cout << "Device clock offset: "
                      << clockOffset << " seconds\n";
        }

        else if (choice == 2) {
            std::string code;

            std::cout << "Enter TOTP code: ";
            std::cin >> code;

            uint64_t serverTime = getCurrentTime();

            VerifyResult result = verifier.verify(code, serverTime);

            std::cout << "\nVerification result: ";

            if (result.accepted) {
                std::cout << "ACCEPTED\n";
                std::cout << "Matched offset: "
                          << result.matchedOffset << "\n";
            } else {
                std::cout << "REJECTED\n";
            }

            std::cout << "Reason: " << result.reason << "\n";
            std::cout << "Failed attempts: "
                      << verifier.failures() << "\n";

            if (verifier.locked()) {
                std::cout << "Account locked due to failed attempts.\n";
            }
        }

        else if (choice == 3) {
            std::cout << "Enter acceptance window (0 or 1): ";

            int newWindow;
            std::cin >> newWindow;

            if (newWindow == 0 || newWindow == 1) {
                window = newWindow;
                verifier.setWindow(window);
                std::cout << "Acceptance window updated.\n";
            } else {
                std::cout << "Invalid window. Choose 0 or 1.\n";
            }
        }

        else if (choice == 4) {
            std::cout << "Enter device clock offset in seconds: ";

            std::cin >> clockOffset;

            std::cout << "Clock offset updated.\n";
        }

        else {
            std::cout << "Invalid option. Try again.\n";
        }
    }

    return 0;
}
