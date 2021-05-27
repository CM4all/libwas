/*
 * Copyright 2010-2021 CM4all GmbH
 * All rights reserved.
 *
 * author: Max Kellermann <mk@cm4all.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * FOUNDATION OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "iterator.hxx"

#include <was/simple.h>

struct was_simple_iterator {
    std::multimap<std::string, std::string>::const_iterator i, end;

    struct was_simple_pair pair;
};

struct was_simple_iterator *
was_simple_iterator_new(std::multimap<std::string, std::string>::const_iterator begin,
                        std::multimap<std::string, std::string>::const_iterator end)
{
    auto *i = new was_simple_iterator();

    i->i = begin;
    i->end = end;

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
