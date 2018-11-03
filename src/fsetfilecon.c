#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "selinux_internal.h"
#include "policy.h"

int fsetfilecon(int fd, const char *context)
{
#if defined(__ANDROID__)
	if (is_selinux_enabled() <= 0)
		return 0;
#endif

	return fsetxattr(fd, XATTR_NAME_SELINUX, context, strlen(context) + 1,
			 0);
}

