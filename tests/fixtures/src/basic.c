/* basic.c: first test program. Plain integer code: a loop and a call.
 * Built without a C runtime; mainCRTStartup is the linker's default entry point. */

static int add(int a, int b)
{
    return a + b;
}

int mainCRTStartup(void)
{
    int total = 0;
    for (int i = 0; i < 10; i++) {
        total = add(total, i);
    }
    return total;
}
