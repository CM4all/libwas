// SPDX-License-Identifier: BSD-2-Clause
// author: Max Kellermann <max.kellermann@gmail.com>

#pragma once

#include <cstring> // for std::memcpy()

/**
 * Load an unaligned (maybe misaligned) value from memory.
 */
template<typename T>
[[nodiscard]] [[gnu::pure]] [[gnu::nonnull]]
static inline T
LoadUnaligned(const void *src) noexcept
{
	T value;
	std::memcpy(&value, src, sizeof(value));
	return value;
}

/**
 * Store a value to an unaligned (maybe misaligned) pointer.
 */
template<typename T>
[[gnu::nonnull]]
static inline void
StoreUnaligned(void *dest, const T &value) noexcept
{
	std::memcpy(dest, &value, sizeof(value));
}
