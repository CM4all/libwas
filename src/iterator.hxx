/*
 * GHashTable iterator.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#include <map>
#include <string>

struct was_simple_iterator *
was_simple_iterator_new(const std::map<std::string, std::string> &map);
