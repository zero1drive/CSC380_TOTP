
#include "totp.h"
#include "verifier.h"

#include <charconv>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>

// Get the current Unix time in seconds.
uint64_t getCurrentTime() {
    auto now = std::chrono::system_clock::now();

    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()
    );

    return static_cast<uint64_t>(seconds.count());
}

// Read a complete integer line.
// Reject letters and mixed input such as "12abc".
bool readInteger(const std::string& prompt, int64_t& value) {
    std::string input;

    std::cout << prompt;

    if (!std::getline(std::cin, input)) {
        return false;
    }

    // Remove whitespace around the input.
    size_t start = input.find_first_not_of(" \t\r\n");

    if (start == std::string::npos) {
        return false;
    }

    size_t end = input.find_last_not_of(" \t\r\n");

    std::string number = input.substr(start, end - start + 1);

    const char* first = number.data();
    const char* last = first + number.size();

    // Allow a leading plus sign.
    if (*first == '+') {
        ++first;

        if (first == last) {
            return false;
        }
    }

    int64_t parsed;

    auto result = std::from_chars(first, last, parsed);

    if (result.ec != std::errc{} || result.ptr != last) {
        return false;
    }

    value = parsed;
    return true;
}

int main() {
    const std::string secret = "CSC380-TOTP-demo-secret";

    const int stepSeconds = 30;
    const int digits = 6;
    const int maxAttempts = 5;

    int window = 0;
    int64_t clockOffset = 0;

    // Allow up to 5 consecutive incorrect attempts.
    TotpVerifier verifier(
        secret, window, maxAttempts, stepSeconds, digits
    );

    while (true) {
        std::cout << "\n====================================\n";
        std::cout << "       TOTP AUTHENTICATION DEMO\n";
        std::cout << "====================================\n";

        std::cout << "Current acceptance window: "
                  << window << "\n";

        std::cout << "Device clock offset: "
                  << clockOffset << " seconds\n\n";

        std::cout << "1. Generate TOTP code\n";
        std::cout << "2. Verify TOTP code\n";
        std::cout << "3. Change acceptance window\n";
        std::cout << "4. Set device clock offset\n";
        std::cout << "5. Reset settings\n";
        std::cout << "6. Exit\n";

        int64_t choice;

        if (!readInteger("\nChoose an option: ", choice)) {
            if (std::cin.eof()) {
                std::cout << "\nInput closed. Exiting TOTP demo.\n";
                break;
            }

            std::cout << "Invalid input. "
                      << "Please enter a menu number (1-6).\n";
            continue;
        }

        // Exit.
        if (choice == 6) {
            std::cout << "Exiting TOTP demo.\n";
            break;
        }

        // Generate TOTP code.
        else if (choice == 1) {
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

            std::cout << "\nGenerated TOTP code: "
                      << code << "\n";

            std::cout << "Device clock offset: "
                      << clockOffset << " seconds\n";
        }

        // Verify TOTP code.
        else if (choice == 2) {
            std::string code;

            std::cout << "Enter TOTP code: ";

            if (!std::getline(std::cin, code)) {
                std::cout << "\nInput closed. Exiting TOTP demo.\n";
                break;
            }

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

            std::cout << "Reason: "
                      << result.reason << "\n";

            std::cout << "Failed attempts: "
                      << verifier.failures() << "\n";

            if (verifier.locked()) {
                std::cout << "Account locked due to failed attempts.\n";
            }
        }

        // Change acceptance window.
        else if (choice == 3) {
            int64_t newWindow;

            if (!readInteger(
                    "Enter acceptance window (0 or 1): ",
                    newWindow
                )) {

                if (std::cin.eof()) {
                    std::cout << "\nInput closed. Exiting TOTP demo.\n";
                    break;
                }

                std::cout << "Invalid input. Enter 0 or 1.\n";
                continue;
            }

            if (newWindow == 0 || newWindow == 1) {
                window = static_cast<int>(newWindow);

                verifier.setWindow(window);

                std::cout << "Acceptance window updated.\n";
            } else {
                std::cout << "Invalid window. Choose 0 or 1.\n";
            }
        }

        // Set device clock offset.
        else if (choice == 4) {
            int64_t newOffset;

            if (!readInteger(
                    "Enter device clock offset in seconds: ",
                    newOffset
                )) {

                if (std::cin.eof()) {
                    std::cout << "\nInput closed. Exiting TOTP demo.\n";
                    break;
                }

                std::cout << "Invalid input. "
                          << "Enter a whole number of seconds.\n";
                continue;
            }

            clockOffset = newOffset;

            std::cout << "Clock offset updated.\n";
        }

        // Reset settings.
        else if (choice == 5) {
            window = 0;
            clockOffset = 0;

            // Recreate the verifier to reset failed attempts.
            verifier = TotpVerifier(
                secret, window, maxAttempts, stepSeconds, digits
            );

            std::cout << "Settings reset successfully.\n";
            std::cout << "Acceptance window: 0\n";
            std::cout << "Device clock offset: 0 seconds\n";
            std::cout << "Failed attempts: 0\n";
        }

        // Handle unsupported menu choices.
        else {
            std::cout << "Invalid option. "
                      << "Choose a number from 1 to 6.\n";
        }
    }

    return 0;
}
