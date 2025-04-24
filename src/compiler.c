#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <llvm-c/Core.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/BitWriter.h>
#include <llvm-c/Target.h>
#include <llvm-c/Transforms/Scalar.h>
#include <llvm-c/Transforms/IPO.h>
#include "compiler.h"
#include "ast.h"
#include "symbol_table.h"
#include "codegen_utils.h"
#include "codegen_decl.h"
#include "error.h"

/* Initialize default compiler options */
void init_compiler_options(CompilerOptions *options) {
    if (!options) return;
    
    options->input_file = NULL;
    options->output_file = NULL;
    options->module_name = "iwb_module";
    options->target_triple = NULL;  /* Use default target */
    options->optimization_level = 0;
    options->emit_debug_info = 0;
    options->verbose = 0;
    options->dump_ast = 0;
    options->dump_llvm_ir = 0;
    options->verify_module = 0;
}

/* Initialize the compiler */
void init_compiler(void) {
    /* Initialize LLVM */
    LLVMInitializeCore(LLVMGetGlobalPassRegistry());
    LLVMInitializeAllTargetInfos();
    LLVMInitializeAllTargets();
    LLVMInitializeAllTargetMCs();
    LLVMInitializeAllAsmParsers();
    LLVMInitializeAllAsmPrinters();
    
    /* Reset error counters */
    reset_error_counters();
}

/* Clean up compiler resources */
void cleanup_compiler(void) {
    /* Nothing to do for now */
}

/* Compile a source file to LLVM bitcode */
int compile_file(const char *input_file, const char *output_file, CompilerOptions *options) {
    if (!input_file || !output_file || !options) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_OPERATION, "Invalid compiler arguments");
        return 0;
    }
    
    if (options->verbose) {
        printf("Compiling %s to %s\n", input_file, output_file);
    }
    
    /* Parse the input file to an AST */
    ASTNode *ast = parse_file(input_file);
    if (!ast) {
        report_error_simple(ERROR_ERROR, ERR_FILE_OPEN, "Failed to parse input file");
        return 0;
    }
    
    /* Dump AST if requested */
    if (options->dump_ast) {
        printf("AST for %s:\n", input_file);
        print_ast(ast, 0);
        printf("\n");
    }
    
    /* Compile the AST to LLVM bitcode */
    int result = compile_ast(ast, output_file, options);
    
    /* Free the AST */
    free_ast_node(ast);
    
    return result;
}

/* Compile an AST to LLVM bitcode */
int compile_ast(ASTNode *ast, const char *output_file, CompilerOptions *options) {
    if (!ast || !output_file || !options) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_OPERATION, "Invalid compiler arguments");
        return 0;
    }
    
    /* Create LLVM module */
    LLVMModuleRef module = create_module(options->module_name);
    if (!module) {
        report_error_simple(ERROR_ERROR, ERR_LLVM_ERROR, "Failed to create LLVM module");
        return 0;
    }
    
    /* Set target triple if specified */
    if (options->target_triple) {
        LLVMSetTarget(module, options->target_triple);
    }
    
    /* Create builder */
    LLVMBuilderRef builder = create_builder();
    if (!builder) {
        LLVMDisposeModule(module);
        report_error_simple(ERROR_ERROR, ERR_LLVM_ERROR, "Failed to create LLVM builder");
        return 0;
    }
    
    /* Create symbol table */
    SymbolTable *symbol_table = create_symbol_table(256, NULL);
    if (!symbol_table) {
        LLVMDisposeBuilder(builder);
        LLVMDisposeModule(module);
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to create symbol table");
        return 0;
    }
    
    /* Declare standard library functions */
    declare_standard_library(module, symbol_table);
    
    /* Generate forward declarations for all functions */
    if (!generate_function_forward_declarations(ast, module, symbol_table)) {
        free_symbol_table(symbol_table);
        LLVMDisposeBuilder(builder);
        LLVMDisposeModule(module);
        report_error_simple(ERROR_ERROR, ERR_LLVM_ERROR, "Failed to generate function forward declarations");
        return 0;
    }
    
    /* Generate code for the program */
    if (!generate_program(ast, module, builder, symbol_table)) {
        free_symbol_table(symbol_table);
        LLVMDisposeBuilder(builder);
        LLVMDisposeModule(module);
        report_error_simple(ERROR_ERROR, ERR_LLVM_ERROR, "Failed to generate code");
        return 0;
    }
    
    /* Verify module if requested */
    if (options->verify_module) {
        if (!verify_module(module)) {
            free_symbol_table(symbol_table);
            LLVMDisposeBuilder(builder);
            LLVMDisposeModule(module);
            report_error_simple(ERROR_ERROR, ERR_LLVM_ERROR, "Module verification failed");
            return 0;
        }
    }
    
    /* Optimize module if requested */
    if (options->optimization_level > 0) {
        if (!optimize_module(module, options->optimization_level)) {
            free_symbol_table(symbol_table);
            LLVMDisposeBuilder(builder);
            LLVMDisposeModule(module);
            report_error_simple(ERROR_ERROR, ERR_LLVM_ERROR, "Module optimization failed");
            return 0;
        }
    }
    
    /* Dump LLVM IR if requested */
    if (options->dump_llvm_ir) {
        char *ir = LLVMPrintModuleToString(module);
        printf("LLVM IR for %s:\n%s\n", options->input_file, ir);
        LLVMDisposeMessage(ir);
    }
    
    /* Write module to output file */
    if (!write_module_to_file(module, output_file)) {
        free_symbol_table(symbol_table);
        LLVMDisposeBuilder(builder);
        LLVMDisposeModule(module);
        report_error_simple(ERROR_ERROR, ERR_FILE_WRITE, "Failed to write output file");
        return 0;
    }
    
    /* Clean up */
    free_symbol_table(symbol_table);
    LLVMDisposeBuilder(builder);
    LLVMDisposeModule(module);
    
    if (options->verbose) {
        printf("Successfully compiled to %s\n", output_file);
    }
    
    return 1;
}

/* Optimize LLVM module */
int optimize_module(LLVMModuleRef module, int optimization_level) {
    if (!module || optimization_level < 0 || optimization_level > 3) {
        return 0;
    }
    
    /* Create pass manager */
    LLVMPassManagerRef pass_manager = LLVMCreatePassManager();
    if (!pass_manager) {
        return 0;
    }
    
    /* Add optimization passes based on level */
    if (optimization_level >= 1) {
        /* Basic optimizations */
        LLVMAddInstructionCombiningPass(pass_manager);
        LLVMAddReassociatePass(pass_manager);
        LLVMAddGVNPass(pass_manager);
        LLVMAddCFGSimplificationPass(pass_manager);
    }
    
    if (optimization_level >= 2) {
        /* More aggressive optimizations */
        LLVMAddPromoteMemoryToRegisterPass(pass_manager);
        LLVMAddTailCallEliminationPass(pass_manager);
        LLVMAddJumpThreadingPass(pass_manager);
        LLVMAddDeadStoreEliminationPass(pass_manager);
    }
    
    if (optimization_level >= 3) {
        /* Most aggressive optimizations */
        LLVMAddFunctionInliningPass(pass_manager);
        LLVMAddGlobalDCEPass(pass_manager);
    }
    
    /* Run optimizations */
    LLVMRunPassManager(pass_manager, module);
    
    /* Clean up */
    LLVMDisposePassManager(pass_manager);
    
    return 1;
}

/* Verify LLVM module */
int verify_module(LLVMModuleRef module) {
    if (!module) {
        return 0;
    }
    
    char *error_message = NULL;
    int result = !LLVMVerifyModule(module, LLVMPrintMessageAction, &error_message);
    
    if (error_message) {
        LLVMDisposeMessage(error_message);
    }
    
    return result;
}

/* Parse a source file to an AST */
ASTNode *parse_file(const char *input_file) {
    /* This is a placeholder - in a real implementation, this would call the parser */
    /* For now, we'll just return NULL to indicate failure */
    report_error_simple(ERROR_ERROR, ERR_INVALID_OPERATION, "Parser not implemented yet");
    return NULL;
}

/* Parse a source string to an AST */
ASTNode *parse_string(const char *source) {
    /* This is a placeholder - in a real implementation, this would call the parser */
    /* For now, we'll just return NULL to indicate failure */
    report_error_simple(ERROR_ERROR, ERR_INVALID_OPERATION, "Parser not implemented yet");
    return NULL;
}

/* Print AST to stdout (for debugging) */
void print_ast(ASTNode *ast, int indent) {
    if (!ast) return;
    
    /* Print indentation */
    for (int i = 0; i < indent; i++) {
        printf("  ");
    }
    
    /* Print node type */
    printf("%s", node_type_to_string(ast->type));
    
    /* Print node-specific information */
    switch (ast->type) {
        case NODE_PROGRAM:
            printf(" (%zu declarations)\n", ast->data.program.declaration_count);
            for (size_t i = 0; i < ast->data.program.declaration_count; i++) {
                print_ast(ast->data.program.declarations[i], indent + 1);
            }
            break;
            
        case NODE_BLOCK:
            printf(" (%zu statements)\n", ast->data.block.statement_count);
            for (size_t i = 0; i < ast->data.block.statement_count; i++) {
                print_ast(ast->data.block.statements[i], indent + 1);
            }
            break;
            
        case NODE_VARIABLE_DECLARATION:
            printf(" %s: %s\n", ast->data.variable_declaration.name, 
                   ast->data.variable_declaration.type);
            if (ast->data.variable_declaration.initializer) {
                print_ast(ast->data.variable_declaration.initializer, indent + 1);
            }
            break;
            
        case NODE_ARRAY_DECLARATION:
            printf(" %s: %s[%zu]\n", ast->data.array_declaration.name, 
                   ast->data.array_declaration.element_type, 
                   ast->data.array_declaration.size);
            for (size_t i = 0; i < ast->data.array_declaration.initializer_count; i++) {
                print_ast(ast->data.array_declaration.initializers[i], indent + 1);
            }
            break;
            
        case NODE_STRUCT_DECLARATION:
            printf(" %s (%zu fields)\n", ast->data.struct_declaration.name, 
                   ast->data.struct_declaration.field_count);
            for (size_t i = 0; i < ast->data.struct_declaration.field_count; i++) {
                for (int j = 0; j < indent + 1; j++) {
                    printf("  ");
                }
                printf("%s: %s\n", ast->data.struct_declaration.fields[i].name, 
                       ast->data.struct_declaration.fields[i].type);
            }
            break;
            
        case NODE_FUNCTION_DECLARATION:
            printf(" %s %s(", ast->data.function_declaration.return_type, 
                   ast->data.function_declaration.name);
            for (size_t i = 0; i < ast->data.function_declaration.param_count; i++) {
                if (i > 0) printf(", ");
                printf("%s: %s", ast->data.function_declaration.params[i].name, 
                       ast->data.function_declaration.params[i].type);
            }
            printf(")\n");
            if (ast->data.function_declaration.body) {
                print_ast(ast->data.function_declaration.body, indent + 1);
            }
            break;
            
        case NODE_VARIABLE:
            printf(" %s\n", ast->data.variable.name);
            break;
            
        case NODE_ARRAY_ACCESS:
            printf("\n");
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("array:\n");
            print_ast(ast->data.array_access.array, indent + 2);
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("index:\n");
            print_ast(ast->data.array_access.index, indent + 2);
            break;
            
        case NODE_STRUCT_ACCESS:
            printf(" .%s\n", ast->data.struct_access.field);
            print_ast(ast->data.struct_access.structure, indent + 1);
            break;
            
        case NODE_FUNCTION_CALL:
            printf(" %s (%zu args)\n", ast->data.function_call.name, 
                   ast->data.function_call.arg_count);
            for (size_t i = 0; i < ast->data.function_call.arg_count; i++) {
                print_ast(ast->data.function_call.args[i], indent + 1);
            }
            break;
            
        case NODE_ASSIGNMENT:
            printf(" %s\n", ast->data.assignment.op);
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("lhs:\n");
            print_ast(ast->data.assignment.lhs, indent + 2);
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("rhs:\n");
            print_ast(ast->data.assignment.rhs, indent + 2);
            break;
            
        case NODE_BINARY_OP:
            printf(" %s\n", ast->data.binary_op.op);
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("left:\n");
            print_ast(ast->data.binary_op.left, indent + 2);
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("right:\n");
            print_ast(ast->data.binary_op.right, indent + 2);
            break;
            
        case NODE_UNARY_OP:
            printf(" %s (is_prefix: %d)\n", ast->data.unary_op.op, 
                   ast->data.unary_op.is_prefix);
            print_ast(ast->data.unary_op.operand, indent + 1);
            break;
            
        case NODE_TERNARY_OP:
            printf("\n");
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("condition:\n");
            print_ast(ast->data.ternary_op.condition, indent + 2);
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("then_expr:\n");
            print_ast(ast->data.ternary_op.then_expr, indent + 2);
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("else_expr:\n");
            print_ast(ast->data.ternary_op.else_expr, indent + 2);
            break;
            
        case NODE_CAST:
            printf(" to %s\n", ast->data.cast.type);
            print_ast(ast->data.cast.expr, indent + 1);
            break;
            
        case NODE_INTEGER_LITERAL:
            printf(" %d\n", ast->data.integer_literal);
            break;
            
        case NODE_FLOAT_LITERAL:
            printf(" %f\n", ast->data.float_literal);
            break;
            
        case NODE_STRING_LITERAL:
            printf(" \"%s\"\n", ast->data.string_literal);
            break;
            
        case NODE_IF_STATEMENT:
            printf("\n");
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("condition:\n");
            print_ast(ast->data.if_statement.condition, indent + 2);
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("then_branch:\n");
            print_ast(ast->data.if_statement.then_branch, indent + 2);
            if (ast->data.if_statement.else_branch) {
                for (int i = 0; i < indent + 1; i++) {
                    printf("  ");
                }
                printf("else_branch:\n");
                print_ast(ast->data.if_statement.else_branch, indent + 2);
            }
            break;
            
        case NODE_WHILE_STATEMENT:
            printf("\n");
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("condition:\n");
            print_ast(ast->data.while_statement.condition, indent + 2);
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("body:\n");
            print_ast(ast->data.while_statement.body, indent + 2);
            break;
            
        case NODE_FOR_STATEMENT:
            printf("\n");
            if (ast->data.for_statement.init) {
                for (int i = 0; i < indent + 1; i++) {
                    printf("  ");
                }
                printf("init:\n");
                print_ast(ast->data.for_statement.init, indent + 2);
            }
            if (ast->data.for_statement.condition) {
                for (int i = 0; i < indent + 1; i++) {
                    printf("  ");
                }
                printf("condition:\n");
                print_ast(ast->data.for_statement.condition, indent + 2);
            }
            if (ast->data.for_statement.update) {
                for (int i = 0; i < indent + 1; i++) {
                    printf("  ");
                }
                printf("update:\n");
                print_ast(ast->data.for_statement.update, indent + 2);
            }
            for (int i = 0; i < indent + 1; i++) {
                printf("  ");
            }
            printf("body:\n");
            print_ast(ast->data.for_statement.body, indent + 2);
            break;
            
        case NODE_RETURN_STATEMENT:
            printf("\n");
            if (ast->data.return_statement.expr) {
                print_ast(ast->data.return_statement.expr, indent + 1);
            }
            break;
            
        case NODE_BREAK_STATEMENT:
            printf("\n");
            break;
            
        case NODE_CONTINUE_STATEMENT:
            printf("\n");
            break;
            
        case NODE_EXPRESSION_STATEMENT:
            printf("\n");
            print_ast(ast->data.expression_statement.expr, indent + 1);
            break;
            
        default:
            printf(" (unknown node type)\n");
            break;
    }
}

/* Helper function to convert node type to string */
const char *node_type_to_string(ASTNodeType type) {
    switch (type) {
        case NODE_PROGRAM: return "PROGRAM";
        case NODE_BLOCK: return "BLOCK";
        case NODE_VARIABLE_DECLARATION: return "VARIABLE_DECLARATION";
        case NODE_ARRAY_DECLARATION: return "ARRAY_DECLARATION";
        case NODE_STRUCT_DECLARATION: return "STRUCT_DECLARATION";
        case NODE_FUNCTION_DECLARATION: return "FUNCTION_DECLARATION";
        case NODE_VARIABLE: return "VARIABLE";
        case NODE_ARRAY_ACCESS: return "ARRAY_ACCESS";
        case NODE_STRUCT_ACCESS: return "STRUCT_ACCESS";
        case NODE_FUNCTION_CALL: return "FUNCTION_CALL";
        case NODE_ASSIGNMENT: return "ASSIGNMENT";
        case NODE_BINARY_OP: return "BINARY_OP";
        case NODE_UNARY_OP: return "UNARY_OP";
        case NODE_TERNARY_OP: return "TERNARY_OP";
        case NODE_CAST: return "CAST";
        case NODE_INTEGER_LITERAL: return "INTEGER_LITERAL";
        case NODE_FLOAT_LITERAL: return "FLOAT_LITERAL";
        case NODE_STRING_LITERAL: return "STRING_LITERAL";
        case NODE_IF_STATEMENT: return "IF_STATEMENT";
        case NODE_WHILE_STATEMENT: return "WHILE_STATEMENT";
        case NODE_FOR_STATEMENT: return "FOR_STATEMENT";
        case NODE_RETURN_STATEMENT: return "RETURN_STATEMENT";
        case NODE_BREAK_STATEMENT: return "BREAK_STATEMENT";
        case NODE_CONTINUE_STATEMENT: return "CONTINUE_STATEMENT";
        case NODE_EXPRESSION_STATEMENT: return "EXPRESSION_STATEMENT";
        default: return "UNKNOWN";
    }
}

