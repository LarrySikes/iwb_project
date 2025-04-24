#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "error.h"

/* Global variables for error handling */
static FILE *error_output = NULL;
static int error_count = 0;
static int warning_count = 0;

/* Initialize error output to stderr by default */
static void init_error_output(void) {
    if (!error_output) {
        error_output = stderr;
    }
}

/* Set output stream for error messages */
void set_error_output(FILE *stream) {
    error_output = stream;
}

/* Reset error and warning counters */
void reset_error_counters(void) {
    error_count = 0;
    warning_count = 0;
}

/* Get the number of errors reported */
int get_error_count(void) {
    return error_count;
}

/* Get the number of warnings reported */
int get_warning_count(void) {
    return warning_count;
}

/* Check if compilation should abort due to errors */
int should_abort_compilation(void) {
    return error_count > 0;
}

/* Get string representation of an error level */
const char *error_level_to_string(ErrorLevel level) {
    switch (level) {
        case ERROR_INFO:    return "INFO";
        case ERROR_WARNING: return "WARNING";
        case ERROR_ERROR:   return "ERROR";
        case ERROR_FATAL:   return "FATAL";
        default:            return "UNKNOWN";
    }
}

/* Get string representation of an error code */
const char *error_code_to_string(ErrorCode code) {
    switch (code) {
        case ERR_NONE:                   return "No error";
        case ERR_MEMORY_ALLOCATION:      return "Memory allocation failed";
        case ERR_FILE_OPEN:              return "Failed to open file";
        case ERR_FILE_WRITE:             return "Failed to write to file";
        case ERR_INVALID_AST:            return "Invalid AST node";
        case ERR_UNDEFINED_SYMBOL:       return "Undefined symbol";
        case ERR_DUPLICATE_SYMBOL:       return "Duplicate symbol definition";
        case ERR_TYPE_MISMATCH:          return "Type mismatch";
        case ERR_INVALID_TYPE:           return "Invalid type";
        case ERR_INVALID_OPERATION:      return "Invalid operation";
        case ERR_INVALID_CAST:           return "Invalid type cast";
        case ERR_INVALID_LVALUE:         return "Invalid lvalue in assignment";
        case ERR_ARRAY_INDEX_OUT_OF_BOUNDS: return "Array index out of bounds";
        case ERR_INVALID_ARRAY_SIZE:     return "Invalid array size";
        case ERR_INVALID_FUNCTION_CALL:  return "Invalid function call";
        case ERR_ARGUMENT_COUNT_MISMATCH: return "Wrong number of arguments";
        case ERR_INVALID_RETURN:         return "Invalid return statement";
        case ERR_INVALID_BREAK:          return "Invalid break statement";
        case ERR_INVALID_CONTINUE:       return "Invalid continue statement";
        case ERR_LLVM_ERROR:             return "LLVM API error";
        case ERR_INTERNAL_ERROR:         return "Internal compiler error";
        default:                         return "Unknown error";
    }
}

/* Report an error with context information */
void report_error(ErrorLevel level, ErrorCode code, const char *message, ErrorContext *context) {
    init_error_output();
    
    /* Update error/warning counters */
    if (level == ERROR_ERROR || level == ERROR_FATAL) {
        error_count++;
    } else if (level == ERROR_WARNING) {
        warning_count++;
    }
    
    /* Print error location if available */
    if (context) {
        fprintf(error_output, "%s:%d:%d: ", 
                context->filename ? context->filename : "<unknown>",
                context->line, 
                context->column);
    }
    
    /* Print error level and code */
    fprintf(error_output, "%s: %s: ", 
            error_level_to_string(level),
            error_code_to_string(code));
    
    /* Print error message */
    fprintf(error_output, "%s\n", message ? message : "Unknown error");
    
    /* Exit on fatal errors */
    if (level == ERROR_FATAL) {
        exit(EXIT_FAILURE);
    }
}

/* Report an error without context information */
void report_error_simple(ErrorLevel level, ErrorCode code, const char *message) {
    report_error(level, code, message, NULL);
}

/* Format an error message with variable arguments */
void report_error_format(ErrorLevel level, ErrorCode code, ErrorContext *context, 
                        const char *format, ...) {
    if (!format) {
        report_error(level, code, "Unknown error", context);
        return;
    }
    
    /* Format the message */
    va_list args;
    va_start(args, format);
    
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    
    va_end(args);
    
    /* Report the error */
    report_error(level, code, buffer, context);
}

