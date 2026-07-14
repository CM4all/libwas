// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include <map>
#include <string>

struct was_simple_iterator *
was_simple_iterator_new(std::multimap<std::string, std::string>::const_iterator begin,
                        std::multimap<std::string, std::string>::const_iterator end);
