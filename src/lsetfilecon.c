#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "selinux_internal.h"
#include "policy.h"

int lsetfilecon(const char *path, const char *context)
{
#if !defined(__ANDROID__)
	return lsetxattr(path, XATTR_NAME_SELINUX, context, strlen(context) + 1,
			 0);
#else
	return 0;
#endif
}

