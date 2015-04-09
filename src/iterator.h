/*
 * GHashTable iterator.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#include <glib.h>

struct was_simple_iterator *
was_simple_new_iterator(GHashTable *ht);
