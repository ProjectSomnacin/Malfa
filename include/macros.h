#ifndef macros_h
#define macros_h

#include <stdio.h>

#ifdef DEBUG
#define BUILD_TYPE "DEBUG"
#else
#define BUILD_TYPE "RELEASE"
#endif

#define info(a ...) ({printf(a),printf("\n");})
#define error(a ...) ({printf("[Error] "),printf(a),printf("\n");})
#ifdef DEBUG
# define debug(a ...) ({printf("[DEBUG] "),printf(a),printf("\n");})
#else
# define debug(a ...)
#endif

#define safeFree(ptr) ({if (ptr) {free(ptr); ptr=NULL;}})

#define cassure(a) do{ if ((a) == 0){err=__LINE__; goto error;} }while(0)
#define cretassure(cond, errstr ...) do{ if ((cond) == 0){err=__LINE__;error(errstr); goto error;} }while(0)


#endif /* macros_h */