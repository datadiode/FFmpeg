#include "locale.h"
#include <stdlib.h>
#include <string.h>
#include "windows.h"

#define MAXENV 32
static char *envnames[MAXENV];
static char *envvars[MAXENV];

static void cleanup_libc(void)
{
	int i;
	for (i=0; i <MAXENV; i++) {
		if (envnames[i])
			free(envnames[i]);
		if (envvars[i])
			free(envvars[i]);
	}
}

char *getenv(const char *name)
{
	int i;
	for (i=0; i < MAXENV; i++) {
		if (envnames[i] && !strcmp(envnames[i], name))
			return envvars[i];
	}
	return NULL;
}

int setenv(const char *name, const char *value, int overwrite)
{
	int i;
	char *val;
	for (i=0; i < MAXENV; i++) {
		if (envnames[i] && !strcmp(envnames[i], name)) {
			if (overwrite) {
				val = _strdup(value);
				if (!val)
					return -1;
				if (envvars[i])
					free(envvars[i]);
				envvars[i] = val;
			}
			return 0;
		}
	}
	for (i=0; i < MAXENV; i++) {
		if (!envnames[i]) {
			envnames[i] = _strdup(name);
			envvars[i] = _strdup(value);
			if (!envnames[i] || !envvars[i]) {
				if (envnames[i])
					free(envnames[i]);
				if (envvars[i])
					free(envvars[i]);
				envnames[i] = NULL;
				envvars[i] = NULL;
				return -1;
			}
			return 0;
		}
	}
	return -1;
}

int unsetenv(const char *name)
{
	int i;
	for (i=0; i < MAXENV; i++) {
		if (envnames[i] && !strcmp(envnames[i], name)) {
			free(envnames[i]);
			envnames[i] = NULL;
			if (envvars[i])
				free(envvars[i]);
			envvars[i] = NULL;
		}
	}
	return 0;
}
