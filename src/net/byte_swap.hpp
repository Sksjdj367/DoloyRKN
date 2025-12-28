// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

namespace Net
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static inline uint16_t NetToHostShort(uint16_t val) { return val; }

static inline uint32_t NetToHostLong(uint32_t val) { return val; }

static inline uint16_t HostToNetShort(uint16_t val) { return val; }

static inline uint32_t HostToNetLong(uint32_t val) { return val; }
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static inline uint16_t NetToHostShort(uint16_t val) { return __builtin_bswap16(val); }

static inline uint32_t NetToHostLong(uint32_t val) { return __builtin_bswap32(val); }

static inline uint16_t HostToNetShort(uint16_t val) { return __builtin_bswap16(val); }

static inline uint32_t HostToNetLong(uint32_t val) { return __builtin_bswap32(val); }
#else
#error "Cannot define byte swap functions for targeted platform because __BYTE_ORDER__ is undefined"
#endif
} // namespace Net
