// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#ifndef WAS_COMPILER_H
#define WAS_COMPILER_H

#ifdef __GNUC__
#  define was_gcc_pure __attribute__((pure))
#  define was_gcc_unused __attribute__((unused))
#  define was_gcc_printf(string_index, first_to_check) __attribute__((format(printf, string_index, first_to_check)))
#  define was_gcc_unreachable() __builtin_unreachable()
#else
#  define was_gcc_pure
#  define was_gcc_unused
#  define was_gcc_printf(string_index, first_to_check)
#  define was_gcc_unreachable()
#endif

#endif
