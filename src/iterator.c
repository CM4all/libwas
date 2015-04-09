/*
 * GHashTable iterator.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#include "iterator.h"

#include <was/simple.h>

struct was_simple_iterator {
    GHashTableIter iter;

    struct was_simple_pair pair;
};

struct was_simple_iterator *
was_simple_new_iterator(GHashTable *ht)
{
    struct was_simple_iterator *i = g_new(struct was_simple_iterator, 1);

    g_hash_table_iter_init(&i->iter, ht);
    return i;
}

void
was_simple_iterator_free(struct was_simple_iterator *i)
{
    g_free(i);
}

const struct was_simple_pair *
was_simple_iterator_next(struct was_simple_iterator *i)
{
    gpointer key, value;

    if (!g_hash_table_iter_next(&i->iter, &key, &value))
        return NULL;

    i->pair.name = key;
    i->pair.value = value;
    return &i->pair;
}
