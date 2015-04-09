/*
 * GHashTable iterator.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#include "iterator.hxx"

#include <was/simple.h>

struct was_simple_iterator {
    GHashTableIter iter;

    struct was_simple_pair pair;
};

struct was_simple_iterator *
was_simple_new_iterator(GHashTable *ht)
{
    auto *i = new was_simple_iterator();

    g_hash_table_iter_init(&i->iter, ht);
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
    gpointer key, value;

    if (!g_hash_table_iter_next(&i->iter, &key, &value))
        return nullptr;

    i->pair.name = (const char *)key;
    i->pair.value = (const char *)value;
    return &i->pair;
}
