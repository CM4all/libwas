// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

/*
 * Synchronous server implementation of the Multi Web Application
 * Socket protocol.
 */

#include <was/multi.h>
#include <was/simple.h>
#include <was/protocol.h>

#include <cstddef>

#include <sys/socket.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

struct was_multi {
    static constexpr int fd = 0;
};

struct was_multi *
was_multi_new()
{
    return new was_multi{};
}

void
was_multi_free(struct was_multi *m)
{
    delete m;
}

int
was_multi_fd(struct was_multi *m)
{
    return m->fd;
}

static const int *
ExpectFds(struct msghdr &msg, std::size_t expect) noexcept
{
    const int *result = nullptr;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    while (cmsg != nullptr) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            if (result != nullptr)
                /* reject duplicate SCM_RIGHTS */
                return nullptr;

            result = (const int *)(const void *)CMSG_DATA(cmsg);
            const size_t n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(result[0]);
            if (n != expect)
                return nullptr;
        }

        cmsg = CMSG_NXTHDR(&msg, cmsg);
    }

    return result;
}

static void
CloseFds(struct msghdr &msg) noexcept
{
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    while (cmsg != nullptr) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            const int *fds = (const int *)(const void *)CMSG_DATA(cmsg);
            const std::size_t n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(fds[0]);

            for (std::size_t i = 0; i < n; ++i)
                close(fds[i]);
        }

        cmsg = CMSG_NXTHDR(&msg, cmsg);
    }
}

struct was_simple *
was_multi_accept_simple(struct was_multi *m)
{
    while (true) {
        struct was_header h;

        struct iovec v[] = {
            {&h, sizeof(h)},
        };

        static constexpr std::size_t max_fds = 3;
        static constexpr std::size_t CMSG_SIZE = max_fds * sizeof(int);
        static constexpr size_t CMSG_BUFFER_SIZE = CMSG_SPACE(CMSG_SIZE);
        static constexpr size_t CMSG_N_LONGS = (CMSG_BUFFER_SIZE + sizeof(long) - 1) / sizeof(long);
        long cmsg[CMSG_N_LONGS];

        struct msghdr msg{};
        msg.msg_iov = v;
        msg.msg_iovlen = ARRAY_SIZE(v);
        msg.msg_control = cmsg;
        msg.msg_controllen = sizeof(cmsg);

        ssize_t nbytes = recvmsg(m->fd, &msg, MSG_CMSG_CLOEXEC);
        if (nbytes <= 0)
            return NULL;

        if ((std::size_t)nbytes != sizeof(h) ||
            (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC))) {
            CloseFds(msg);
            return nullptr;
        }

        switch (h.command) {
        case MULTI_WAS_COMMAND_NOP:
            CloseFds(msg);
            continue;

        case MULTI_WAS_COMMAND_NEW:
            if (auto fds = ExpectFds(msg, 3))
                return was_simple_new_fds(fds[0], fds[1], fds[2]);

            CloseFds(msg);
            return nullptr;
        }
    }
}
