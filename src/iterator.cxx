/*
 * GHashTable iterator.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#include "iterator.hxx"

#include <was/simple.h>

struct was_simple_iterator {
    std::map<std::string, std::string>::const_iterator i, end;

    struct was_simple_pair pair;
};

struct was_simple_iterator *
was_simple_iterator_new(const std::map<std::string, std::string> &map)
{
    auto *i = new was_simple_iterator();

    i->i = map.begin();
    i->end = map.end();

    return i;
}

void
was_simple_iterator_free(struct was_simple_iterator *i)
{
    delete i;
}

const struct was_simple_pair *
was_simple_iterator_next(struct was_simple_iterator *i)
{
    if (i->i == i->end)
        return nullptr;

    i->pair.name = i->i->first.c_str();
    i->pair.value = i->i->second.c_str();
    ++i->i;

    return &i->pair;
}
