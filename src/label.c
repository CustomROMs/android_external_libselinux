/*
 * Generalized labeling frontend for userspace object managers.
 *
 * Author : Eamon Walsh <ewalsh@epoch.ncsc.mil>
 */

#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <selinux/selinux.h>
#include "callbacks.h"
#include "label_internal.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef int (*selabel_initfunc)(struct selabel_handle *rec,
				const struct selinux_opt *opts,
				unsigned nopts);

static selabel_initfunc initfuncs[] = {
	&selabel_file_init,
	NULL,
	NULL,
	NULL,
	&selabel_property_init,
};

/*
 * Validation functions
 */

static inline int selabel_is_validate_set(const struct selinux_opt *opts,
					  unsigned n)
{
#if !defined(__ANDROID__)
	while (n--)
		if (opts[n].type == SELABEL_OPT_VALIDATE)
			return !!opts[n].value;
#endif
	return 0;
}

int selabel_validate(struct selabel_handle *rec,
		     struct selabel_lookup_rec *contexts)
{
	int rc = 0;
#if !defined(__ANDROID__)
	if (!rec->validating || contexts->validated)
		goto out;

	rc = selinux_validate(&contexts->ctx_raw);
	if (rc < 0)
		goto out;

	contexts->validated = 1;
out:
#endif
	return rc;
}

/*
 * Public API
 */

struct selabel_handle *selabel_open(unsigned int backend,
				    const struct selinux_opt *opts,
				    unsigned nopts)
{
	struct selabel_handle *rec = NULL;

#if !defined(__ANDROID__)
	if (backend >= ARRAY_SIZE(initfuncs)) {
		errno = EINVAL;
		goto out;
	}

	if (initfuncs[backend] == NULL)
		goto out;

	rec = (struct selabel_handle *)malloc(sizeof(*rec));
	if (!rec)
		goto out;

	memset(rec, 0, sizeof(*rec));
	rec->backend = backend;
	rec->validating = selabel_is_validate_set(opts, nopts);

	if ((*initfuncs[backend])(rec, opts, nopts)) {
		free(rec->spec_file);
		free(rec);
		rec = NULL;
	}

out:
#endif
	return rec;
}

static struct selabel_lookup_rec *
selabel_lookup_common(struct selabel_handle *rec,
		      const char *key, int type)
{
	struct selabel_lookup_rec *lr;
	lr = rec->func_lookup(rec, key, type); 
	if (!lr)
		return NULL;

	return lr;
}

int selabel_lookup(struct selabel_handle *rec, char **con,
		   const char *key, int type)
{
#if !defined(__ANDROID__)
	struct selabel_lookup_rec *lr;

	lr = selabel_lookup_common(rec, key, type);
	if (!lr)
		return -1;

	*con = strdup(lr->ctx_raw);
	return *con ? 0 : -1;
#else
	return 0;
#endif
}

bool selabel_partial_match(struct selabel_handle *rec, const char *key)
{
#if !defined(__ANDROID__)
	if (!rec->func_partial_match) {
		/*
		 * If the label backend does not support partial matching,
		 * then assume a match is possible.
		 */
		return true;
	}
	return rec->func_partial_match(rec, key);
#endif
	return false;
}

int selabel_lookup_best_match(struct selabel_handle *rec, char **con,
			      const char *key, const char **aliases, int type)
{
#if !defined(__ANDROID__)
	struct selabel_lookup_rec *lr;

	if (!rec->func_lookup_best_match) {
		errno = ENOTSUP;
		return -1;
	}

	lr = rec->func_lookup_best_match(rec, key, aliases, type);
	if (!lr)
		return -1;

	*con = strdup(lr->ctx_raw);
	return *con ? 0 : -1;
#else
	return 0;
#endif
}

enum selabel_cmp_result selabel_cmp(struct selabel_handle *h1,
				    struct selabel_handle *h2)
{
	if (!h1->func_cmp || h1->func_cmp != h2->func_cmp)
		return SELABEL_INCOMPARABLE;

	return h1->func_cmp(h1, h2);
}

void selabel_close(struct selabel_handle *rec)
{
#if !defined(__ANDROID__)
	rec->func_close(rec);
	free(rec->spec_file);
	free(rec);
#endif
}

void selabel_stats(struct selabel_handle *rec)
{
#if !defined(__ANDROID__)
	rec->func_stats(rec);
#endif
}
