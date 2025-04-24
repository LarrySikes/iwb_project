#ifndef IWB2LLVM_H
#define IWB2LLVM_H

#include <llvm-c/Core.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/BitWriter.h>
#include "ast.h"
#include "symbol_table.h"

/* Main function to compile AST to LLVM IR */
int compile_ast_to_llvm(ASTNode *root, const char *output_file);

/* Type conversion functions */
LLVMTypeRef get_llvm_type(const char *type_name, LLVMModuleRef module, SymbolTable *symbol_table);
LLVMValueRef convert_value(LLVMValueRef value, LLVMTypeRef target_type, LLVMBuilderRef builder);
LLVMValueRef convert_constant_value(LLVMValueRef value, LLVMTypeRef target_type);

/* Expression generation functions */
LLVMValueRef generate_expression(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
LLVMValueRef generate_constant_expression(ASTNode *node, LLVMModuleRef module, SymbolTable *symbol_table);
LLVMValueRef generate_address(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
LLVMValueRef generate_binary_op(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
LLVMValueRef generate_unary_op(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
LLVMValueRef generate_logical_and(ASTNode *left, ASTNode *right, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
LLVMValueRef generate_logical_or(ASTNode *left, ASTNode *right, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
LLVMValueRef generate_assignment(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
LLVMValueRef generate_array_access(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
LLVMValueRef generate_struct_access(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
LLVMValueRef generate_function_call(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
LLVMValueRef generate_ternary_op(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
LLVMValueRef generate_cast(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);

/* Statement generation functions */
int generate_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
int generate_block(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
int generate_if_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
int generate_while_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
int generate_for_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
int generate_return_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);

/* Declaration generation functions */
int generate_struct_declaration(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);
int generate_variable_declaration(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table, int is_global);
int generate_array_declaration(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table, int is_global);
int generate_function_declaration(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, SymbolTable *symbol_table);

#endif /* IWB2LLVM_H */

