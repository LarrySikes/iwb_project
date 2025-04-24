#ifndef ERROR_H
#define ERROR_H

#include <stdio.h>

/* Error severity levels */
typedef enum {
    ERROR_INFO,     /* Informational message */
    ERROR_WARNING,  /* Warning - can continue */
    ERROR_ERROR,    /* Error - may need to abort current operation */
    ERROR_FATAL     /* Fatal error - must abort program */
} ErrorLevel;

/* Error codes */
typedef enum {
    ERR_NONE,                  /* No error */
    ERR_MEMORY_ALLOCATION,     /* Memory allocation failed */
    ERR_FILE_OPEN,             /* Failed to open file */
    ERR_FILE_WRITE,            /* Failed to write to file */
    ERR_INVALID_AST,           /* Invalid AST node */
    ERR_UNDEFINED_SYMBOL,      /* Undefined symbol */
    ERR_DUPLICATE_SYMBOL,      /* Duplicate symbol definition */
    ERR_TYPE_MISMATCH,         /* Type mismatch */
    ERR_INVALID_TYPE,          /* Invalid type */
    ERR_INVALID_OPERATION,     /* Invalid operation */
    ERR_INVALID_CAST,          /* Invalid type cast */
    ERR_INVALID_LVALUE,        /* Invalid lvalue in assignment */
    ERR_ARRAY_INDEX_OUT_OF_BOUNDS, /* Array index out of bounds */
    ERR_INVALID_ARRAY_SIZE,    /* Invalid array size */
    ERR_INVALID_FUNCTION_CALL, /* Invalid function call */
    ERR_ARGUMENT_COUNT_MISMATCH, /* Wrong number of arguments */
    ERR_INVALID_RETURN,        /* Invalid return statement */
    ERR_INVALID_BREAK,         /* Invalid break statement */
    ERR_INVALID_CONTINUE,      /* Invalid continue statement */
    ERR_LLVM_ERROR,            /* LLVM API error */
    ERR_INTERNAL_ERROR         /* Internal compiler error */
} ErrorCode;

/* Error context information */
typedef struct {
    const char *filename;  /* Source file name */
    int line;              /* Line number */
    int column;            /* Column number */
} ErrorContext;

/* Report an error with context information */
void report_error(ErrorLevel level, ErrorCode code, const char *message, ErrorContext *context);

/* Report an error without context information */
void report_error_simple(ErrorLevel level, ErrorCode code, const char *message);

/* Format an error message with variable arguments */
void report_error_format(ErrorLevel level, ErrorCode code, ErrorContext *context, 
                        const char *format, ...);

/* Get string representation of an error code */
const char *error_code_to_string(ErrorCode code);

/* Get string representation of an error level */
const char *error_level_to_string(ErrorLevel level);

/* Set output stream for error messages */
void set_error_output(FILE *stream);

/* Get the number of errors reported */
int get_error_count(void);

/* Get the number of warnings reported */
int get_warning_count(void);

/* Reset error and warning counters */
void reset_error_counters(void);

/* Check if compilation should abort due to errors */
int should_abort_compilation(void);

#endif /* ERROR_H */

