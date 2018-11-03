#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include "selinux_internal.h"
#include "policy.h"

#ifndef SO_PEERSEC
#define SO_PEERSEC 31
#endif

int getpeercon(int fd, char ** context)
{
	char *buf;
	socklen_t size;
	ssize_t ret = 0;

	size = INITCONTEXTLEN + 1;
	buf = malloc(size);
	if (!buf)
		return -1;

#if defined(__ANDROID__)
 	if (is_selinux_enabled() > 0) {
#endif
		memset(buf, 0, size);

		ret = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, buf, &size);
		if (ret < 0 && errno == ERANGE) {
			char *newbuf;

			newbuf = realloc(buf, size);
			if (!newbuf)
				goto out;

			buf = newbuf;
			memset(buf, 0, size);
			ret = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, buf, &size);
		}
	      out:
		if (ret < 0)
			free(buf);
		else
			*context = buf;

#if defined(__ANDROID__)
	} else {
		memset(buf, 0xff, size);
		*context = buf;
	}
#endif
	return ret;
}

