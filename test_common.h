
//#include <usual/base.h>

#include "tinytest.h"
#include "tinytest_macros.h"

#define str_check(a, b) tt_str_op(a, ==, b)
#define int_check(a, b) tt_int_op(a, ==, b)
#define ull_check(a, b) tt_assert_op_type(a, ==, b, uint64_t, "%" PRIu64)

extern struct testcase_t tls_tests[];
