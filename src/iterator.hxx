/*
 * GHashTable iterator.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#include <map>
#include <string>

struct was_simple_iterator *
was_simple_new_iterator(const std::map<std::string, std::string> &map);
