#ifndef CODEGEN_UTILS_H
#define CODEGEN_UTILS_H

#include <llvm-c/Core.h>
#include "ast.h"
#include "symbol_table.h"

/* Utility functions for code generation */

/* Create a new LLVM module with the given name */
LLVMModuleRef create_module(const char *name);

/* Write LLVM module to a bitcode file */
int write_module_to_file(LLVMModuleRef module, const char *filename);

/* Create a new builder for generating instructions */
LLVMBuilderRef create_builder(void);

/* Create standard library function declarations in the module */
void declare_standard_library(LLVMModuleRef module, SymbolTable *symbol_table);

/* Add a printf declaration to the module */
void declare_printf(LLVMModuleRef module, SymbolTable *symbol_table);

/* Add a malloc declaration to the module */
void declare_malloc(LLVMModuleRef module, SymbolTable *symbol_table);

/* Add a free declaration to the module */
void declare_free(LLVMModuleRef module, SymbolTable *symbol_table);

/* Create a global string constant */
LLVMValueRef create_global_string(LLVMModuleRef module, const char *string, const char *name);

/* Create a debug print instruction (for development) */
void create_debug_print(LLVMModuleRef module, LLVMBuilderRef builder, const char *message);

/* Create a debug print instruction for an integer value */
void create_debug_print_int(LLVMModuleRef module, LLVMBuilderRef builder, 
                           LLVMValueRef value, const char *message);

/* Create a debug print instruction for a float value */
void create_debug_print_float(LLVMModuleRef module, LLVMBuilderRef builder, 
                             LLVMValueRef value, const char *message);

/* Create a debug print instruction for a string value */
void create_debug_print_string(LLVMModuleRef module, LLVMBuilderRef builder, 
                              LLVMValueRef value, const char *message);

#endif /* CODEGEN_UTILS_H */

