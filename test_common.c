#include <sys/types.h>
#include <stddef.h>

#include "test_common.h"

struct testgroup_t groups[] = {
	{ "tls/", tls_tests },
	END_OF_GROUPS
};

int main(int argc, const char *argv[])
{
	return tinytest_main(argc, argv, groups);
}

