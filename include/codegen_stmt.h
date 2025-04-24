#ifndef CODEGEN_STMT_H
#define CODEGEN_STMT_H

#include <llvm-c/Core.h>
#include "ast.h"
#include "symbol_table.h"

/* Functions for generating LLVM IR for statements */

/* Generate code for any statement */
int generate_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                      SymbolTable *symbol_table);

/* Generate code for a block of statements */
int generate_block(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                  SymbolTable *symbol_table);

/* Generate code for an if statement */
int generate_if_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                         SymbolTable *symbol_table);

/* Generate code for a while statement */
int generate_while_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                            SymbolTable *symbol_table);

/* Generate code for a for statement */
int generate_for_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                          SymbolTable *symbol_table);

/* Generate code for a return statement */
int generate_return_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                             SymbolTable *symbol_table);

/* Generate code for a break statement */
int generate_break_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                            SymbolTable *symbol_table);

/* Generate code for a continue statement */
int generate_continue_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                               SymbolTable *symbol_table);

/* Generate code for an expression statement */
int generate_expression_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                                 SymbolTable *symbol_table);

/* Loop context for handling break/continue statements */
typedef struct LoopContext {
    LLVMBasicBlockRef continue_block;
    LLVMBasicBlockRef break_block;
    struct LoopContext *parent;
} LoopContext;

/* Create a new loop context */
LoopContext *create_loop_context(LLVMBasicBlockRef continue_block, LLVMBasicBlockRef break_block, 
                                LoopContext *parent);

/* Free a loop context */
void free_loop_context(LoopContext *context);

/* Get the current loop context */
extern LoopContext *current_loop_context;

/* Push a loop context onto the stack */
void push_loop_context(LLVMBasicBlockRef continue_block, LLVMBasicBlockRef break_block);

/* Pop a loop context from the stack */
void pop_loop_context(void);

#endif /* CODEGEN_STMT_H */

