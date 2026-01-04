// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

namespace Platform
{
constexpr auto name = "DoloyRKN";
constexpr auto version = "0.0.3-rc3";
constexpr auto os =
#ifdef __linux__
    "Linux"
#elif defined(__WIN32) || defined(__WIN64)
    "Windows"
#else
#error "Unknown platform"
#endif
    ;
constexpr auto arch =
#if defined(__amd64__) || defined(__x86_64__) || defined(_M_X64) || defined(_WIN64)
    "x86_64";
#elif defined(i386) || defined(__i386__) || defined(_M_IX86)
    "x86"
#elif defined(__aarch64__) || defined(_M_ARM64)
    "ARM64"
#elif defined(__arm__)
    "ARM"
#else
#error "Unknown arch"
#endif
;
} // namespace Platform