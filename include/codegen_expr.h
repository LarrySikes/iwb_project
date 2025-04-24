#ifndef CODEGEN_EXPR_H
#define CODEGEN_EXPR_H

#include <llvm-c/Core.h>
#include "ast.h"
#include "symbol_table.h"

/* Functions for generating LLVM IR for expressions */

/* Generate code for any expression */
LLVMValueRef generate_expression(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                                SymbolTable *symbol_table);

/* Generate code for a constant expression (compile-time evaluation) */
LLVMValueRef generate_constant_expression(ASTNode *node, LLVMModuleRef module, 
                                         SymbolTable *symbol_table);

/* Generate code to get the address of an expression (for lvalues) */
LLVMValueRef generate_address(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                             SymbolTable *symbol_table);

/* Generate code for a binary operation */
LLVMValueRef generate_binary_op(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                               SymbolTable *symbol_table);

/* Generate code for a unary operation */
LLVMValueRef generate_unary_op(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                              SymbolTable *symbol_table);

/* Generate code for a logical AND operation with short-circuit evaluation */
LLVMValueRef generate_logical_and(ASTNode *left, ASTNode *right, LLVMModuleRef module, 
                                 LLVMBuilderRef builder, SymbolTable *symbol_table);

/* Generate code for a logical OR operation with short-circuit evaluation */
LLVMValueRef generate_logical_or(ASTNode *left, ASTNode *right, LLVMModuleRef module, 
                                LLVMBuilderRef builder, SymbolTable *symbol_table);

/* Generate code for an assignment operation */
LLVMValueRef generate_assignment(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                                SymbolTable *symbol_table);

/* Generate code for an array access operation */
LLVMValueRef generate_array_access(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                                  SymbolTable *symbol_table);

/* Generate code for a struct field access operation */
LLVMValueRef generate_struct_access(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                                   SymbolTable *symbol_table);

/* Generate code for a function call */
LLVMValueRef generate_function_call(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                                   SymbolTable *symbol_table);

/* Generate code for a ternary conditional operation */
LLVMValueRef generate_ternary_op(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                                SymbolTable *symbol_table);

/* Generate code for a type cast operation */
LLVMValueRef generate_cast(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                          SymbolTable *symbol_table);

/* Generate code for a variable reference */
LLVMValueRef generate_variable(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                              SymbolTable *symbol_table);

/* Generate code for an integer literal */
LLVMValueRef generate_integer_literal(ASTNode *node);

/* Generate code for a float literal */
LLVMValueRef generate_float_literal(ASTNode *node);

/* Generate code for a string literal */
LLVMValueRef generate_string_literal(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder);

#endif /* CODEGEN_EXPR_H */

