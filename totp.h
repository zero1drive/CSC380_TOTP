#pragma once

#include <cstdint>
#include <string>

std::string generate_totp(const std::string &secret, uint64_t unixTime,
                          int stepSeconds = 30, int digits = 6);
