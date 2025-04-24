#ifndef COMPILER_H
#define COMPILER_H

#include "ast.h"

/* Compilation options */
typedef struct {
    const char *input_file;     /* Input source file */
    const char *output_file;    /* Output LLVM bitcode file */
    const char *module_name;    /* LLVM module name */
    const char *target_triple;  /* Target triple (e.g., "x86_64-pc-linux-gnu") */
    int optimization_level;     /* Optimization level (0-3) */
    int emit_debug_info;        /* Whether to emit debug information */
    int verbose;                /* Verbose output mode */
    int dump_ast;               /* Dump AST to stdout */
    int dump_llvm_ir;           /* Dump LLVM IR to stdout */
    int verify_module;          /* Verify LLVM module */
} CompilerOptions;

/* Initialize default compiler options */
void init_compiler_options(CompilerOptions *options);

/* Compile a source file to LLVM bitcode */
int compile_file(const char *input_file, const char *output_file, CompilerOptions *options);

/* Compile an AST to LLVM bitcode */
int compile_ast(ASTNode *ast, const char *output_file, CompilerOptions *options);

/* Parse a source file to an AST */
ASTNode *parse_file(const char *input_file);

/* Parse a source string to an AST */
ASTNode *parse_string(const char *source);

/* Print AST to stdout (for debugging) */
void print_ast(ASTNode *ast, int indent);

/* Optimize LLVM module */
int optimize_module(LLVMModuleRef module, int optimization_level);

/* Verify LLVM module */
int verify_module(LLVMModuleRef module);

/* Initialize the compiler */
void init_compiler(void);

/* Clean up compiler resources */
void cleanup_compiler(void);

#endif /* COMPILER_H */

