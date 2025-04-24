#ifndef CODEGEN_DECL_H
#define CODEGEN_DECL_H

#include <llvm-c/Core.h>
#include "ast.h"
#include "symbol_table.h"

/* Functions for generating LLVM IR for declarations */

/* Generate code for a struct declaration */
int generate_struct_declaration(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                               SymbolTable *symbol_table);

/* Generate code for a variable declaration */
int generate_variable_declaration(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                                 SymbolTable *symbol_table, int is_global);

/* Generate code for an array declaration */
int generate_array_declaration(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                              SymbolTable *symbol_table, int is_global);

/* Generate code for a function declaration */
int generate_function_declaration(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                                 SymbolTable *symbol_table);

/* Generate code for a program (top-level declarations) */
int generate_program(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                    SymbolTable *symbol_table);

/* Generate forward declarations for all functions */
int generate_function_forward_declarations(ASTNode *node, LLVMModuleRef module, 
                                          SymbolTable *symbol_table);

/* Get LLVM type from type name */
LLVMTypeRef get_llvm_type(const char *type_name, LLVMModuleRef module, SymbolTable *symbol_table);

/* Convert a value to a different type */
LLVMValueRef convert_value(LLVMValueRef value, LLVMTypeRef target_type, LLVMBuilderRef builder);

/* Convert a constant value to a different type */
LLVMValueRef convert_constant_value(LLVMValueRef value, LLVMTypeRef target_type);

#endif /* CODEGEN_DECL_H */

