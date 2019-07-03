#include "stdio.h"
#include <string.h>

#define MAX_FUNCS 20

int funcCount = 0;
typedef int (*FuncPtr)(int);
const char* funcNames[MAX_FUNCS] = {};
FuncPtr funcs[MAX_FUNCS];

/**
 * This involves some black magic to get the name of the function
 * and index inserted. We create a dummy class with a constructor that
 * does the changes we require, then create an instance of it.
 * This is how we statically initialize the list
 */
#define MY_FUNC(name, nameStr)          \
int func_##name(int a);                 \
class _Dummy##name {                    \
public:                                 \
    _Dummy##name() {                    \
        funcNames[funcCount] = nameStr; \
        funcs[funcCount] = func_##name; \
        funcCount++;                    \
    }                                   \
};                                      \
_Dummy##name instance_##name;           \
const char* getName_##name() {          \
    return nameStr;                     \
}                                       \
int func_##name(int a)

#define INVOKE_FUNC(name, val)   func_##name(val);


MY_FUNC(foobar, "woobar") {
    printf("woobar executing. Got %i\n", a);
    return 0;
}

MY_FUNC(goobar, "joobar") {
    printf("joobar executing. Got %i\n", a);
    return 0;
}

int main() {
    // Look up a function by string
    const char* _funcName = "woobar";
    FuncPtr f;
    for(int i = 0; i < MAX_FUNCS; i++) {
        if (strcmp(funcNames[i], _funcName) == 0) {
            f = funcs[i];
            f(999);
            break;
        }
    }

    // Invoke a function
    INVOKE_FUNC(goobar, 22)
}
