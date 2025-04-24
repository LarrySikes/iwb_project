#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <llvm-c/Core.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/BitWriter.h>
#include "codegen_utils.h"
#include "error.h"

/* Create a new LLVM module */
LLVMModuleRef create_module(const char *module_name) {
    return LLVMModuleCreateWithName(module_name ? module_name : "iwb_module");
}

/* Create a new LLVM builder */
LLVMBuilderRef create_builder(void) {
    return LLVMCreateBuilder();
}

/* Write LLVM module to a bitcode file */
int write_module_to_file(LLVMModuleRef module, const char *filename) {
    if (!module || !filename) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_OPERATION, "Invalid module or filename");
        return 0;
    }
    
    char *error_message = NULL;
    LLVMBool result = LLVMWriteBitcodeToFile(module, filename);
    
    if (result != 0) {
        report_error_format(ERROR_ERROR, ERR_FILE_WRITE, NULL, 
                           "Failed to write bitcode to file: %s", filename);
        return 0;
    }
    
    return 1;
}

/* Get LLVM type from type name */
LLVMTypeRef get_llvm_type(LLVMModuleRef module, const char *type_name) {
    if (!module || !type_name) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_TYPE, "Invalid type name");
        return NULL;
    }
    
    /* Handle basic types */
    if (strcmp(type_name, "void") == 0) {
        return LLVMVoidType();
    } else if (strcmp(type_name, "int") == 0) {
        return LLVMInt32Type();
    } else if (strcmp(type_name, "float") == 0) {
        return LLVMFloatType();
    } else if (strcmp(type_name, "double") == 0) {
        return LLVMDoubleType();
    } else if (strcmp(type_name, "char") == 0) {
        return LLVMInt8Type();
    } else if (strcmp(type_name, "bool") == 0) {
        return LLVMInt1Type();
    } else if (strncmp(type_name, "int", 3) == 0) {
        /* Handle integer types with specific bit widths (e.g., int8, int16, int32, int64) */
        int bit_width = atoi(type_name + 3);
        if (bit_width > 0) {
            return LLVMIntType(bit_width);
        }
    }
    
    /* Handle pointer types (e.g., int*, float*) */
    if (type_name[strlen(type_name) - 1] == '*') {
        char base_type[256];
        strncpy(base_type, type_name, strlen(type_name) - 1);
        base_type[strlen(type_name) - 1] = '\0';
        
        LLVMTypeRef base_llvm_type = get_llvm_type(module, base_type);
        if (base_llvm_type) {
            return LLVMPointerType(base_llvm_type, 0);
        }
    }
    
    /* Handle array types (e.g., int[10]) */
    char *open_bracket = strchr(type_name, '[');
    if (open_bracket) {
        char *close_bracket = strchr(open_bracket, ']');
        if (close_bracket) {
            char base_type[256];
            strncpy(base_type, type_name, open_bracket - type_name);
            base_type[open_bracket - type_name] = '\0';
            
            int size = atoi(open_bracket + 1);
            if (size > 0) {
                LLVMTypeRef base_llvm_type = get_llvm_type(module, base_type);
                if (base_llvm_type) {
                    return LLVMArrayType(base_llvm_type, size);
                }
            }
        }
    }
    
    /* Handle struct types */
    if (strncmp(type_name, "struct ", 7) == 0) {
        const char *struct_name = type_name + 7;
        LLVMTypeRef struct_type = LLVMGetTypeByName(module, struct_name);
        if (struct_type) {
            return struct_type;
        } else {
            report_error_format(ERROR_ERROR, ERR_UNDEFINED_SYMBOL, NULL, 
                               "Undefined struct type: %s", struct_name);
            return NULL;
        }
    }
    
    /* Handle named types (e.g., typedefs or structs) */
    LLVMTypeRef named_type = LLVMGetTypeByName(module, type_name);
    if (named_type) {
        return named_type;
    }
    
    report_error_format(ERROR_ERROR, ERR_INVALID_TYPE, NULL, 
                       "Unknown type: %s", type_name);
    return NULL;
}

/* Create a global string constant */
LLVMValueRef create_global_string(LLVMModuleRef module, LLVMBuilderRef builder, 
                                 const char *string, const char *name) {
    if (!module || !builder || !string) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_OPERATION, "Invalid arguments for global string");
        return NULL;
    }
    
    LLVMValueRef global_str = LLVMBuildGlobalStringPtr(builder, string, name ? name : "str");
    return global_str;
}

/* Create a constant integer value */
LLVMValueRef create_constant_int(int value, LLVMTypeRef type) {
    if (!type) {
        type = LLVMInt32Type();
    }
    
    if (LLVMGetTypeKind(type) != LLVMIntegerTypeKind) {
        report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Expected integer type for constant");
        return NULL;
    }
    
    return LLVMConstInt(type, value, 1); /* Sign-extend the value */
}

/* Create a constant float value */
LLVMValueRef create_constant_float(float value) {
    return LLVMConstReal(LLVMFloatType(), value);
}

/* Create a constant double value */
LLVMValueRef create_constant_double(double value) {
    return LLVMConstReal(LLVMDoubleType(), value);
}

/* Create a constant array */
LLVMValueRef create_constant_array(LLVMTypeRef element_type, LLVMValueRef *values, size_t count) {
    if (!element_type || (!values && count > 0)) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_OPERATION, "Invalid arguments for constant array");
        return NULL;
    }
    
    return LLVMConstArray(element_type, values, count);
}

/* Create a zero-initialized constant array */
LLVMValueRef create_constant_zero_array(LLVMTypeRef element_type, size_t count) {
    if (!element_type || count == 0) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_OPERATION, "Invalid arguments for zero array");
        return NULL;
    }
    
    LLVMTypeRef array_type = LLVMArrayType(element_type, count);
    return LLVMConstNull(array_type);
}

/* Declare standard library functions */
void declare_standard_library(LLVMModuleRef module, SymbolTable *symbol_table) {
    if (!module || !symbol_table) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_OPERATION, "Invalid module or symbol table");
        return;
    }
    
    /* printf function */
    LLVMTypeRef printf_param_types[] = { LLVMPointerType(LLVMInt8Type(), 0) };
    LLVMTypeRef printf_type = LLVMFunctionType(LLVMInt32Type(), printf_param_types, 1, 1);
    LLVMValueRef printf_func = LLVMAddFunction(module, "printf", printf_type);
    add_symbol(symbol_table, "printf", printf_func, printf_type, 1, 1);
    
    /* malloc function */
    LLVMTypeRef malloc_param_types[] = { LLVMInt64Type() };
    LLVMTypeRef malloc_type = LLVMFunctionType(LLVMPointerType(LLVMInt8Type(), 0), 
                                              malloc_param_types, 1, 0);
    LLVMValueRef malloc_func = LLVMAddFunction(module, "malloc", malloc_type);
    add_symbol(symbol_table, "malloc", malloc_func, malloc_type, 1, 1);
    
    /* free function */
    LLVMTypeRef free_param_types[] = { LLVMPointerType(LLVMInt8Type(), 0) };
    LLVMTypeRef free_type = LLVMFunctionType(LLVMVoidType(), free_param_types, 1, 0);
    LLVMValueRef free_func = LLVMAddFunction(module, "free", free_type);
    add_symbol(symbol_table, "free", free_func, free_type, 1, 1);
    
    /* exit function */
    LLVMTypeRef exit_param_types[] = { LLVMInt32Type() };
    LLVMTypeRef exit_type = LLVMFunctionType(LLVMVoidType(), exit_param_types, 1, 0);
    LLVMValueRef exit_func = LLVMAddFunction(module, "exit", exit_type);
    add_symbol(symbol_table, "exit", exit_func, exit_type, 1, 1);
}

/* Generate forward declarations for all functions in the program */
int generate_function_forward_declarations(ASTNode *program, LLVMModuleRef module, 
                                          SymbolTable *symbol_table) {
    if (!program || !module || !symbol_table || program->type != NODE_PROGRAM) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid program AST");
        return 0;
    }
    
    /* Iterate through all declarations in the program */
    for (size_t i = 0; i < program->data.program.declaration_count; i++) {
        ASTNode *decl = program->data.program.declarations[i];
        
        /* Only process function declarations */
        if (decl && decl->type == NODE_FUNCTION_DECLARATION) {
            const char *name = decl->data.function_declaration.name;
            const char *return_type_str = decl->data.function_declaration.return_type;
            
            /* Get return type */
            LLVMTypeRef return_type = get_llvm_type(module, return_type_str);
            if (!return_type) {
                report_error_format(ERROR_ERROR, ERR_INVALID_TYPE, NULL, 
                                   "Invalid return type for function %s: %s", 
                                   name, return_type_str);
                return 0;
            }
            
            /* Create parameter types array */
            size_t param_count = decl->data.function_declaration.param_count;
            LLVMTypeRef *param_types = NULL;
            
            if (param_count > 0) {
                param_types = (LLVMTypeRef *)malloc(param_count * sizeof(LLVMTypeRef));
                if (!param_types) {
                    report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, 
                                       "Failed to allocate parameter types array");
                    return 0;
                }
                
                /* Get parameter types */
                for (size_t j = 0; j < param_count; j++) {
                    const char *param_type_str = decl->data.function_declaration.params[j].type;
                    param_types[j] = get_llvm_type(module, param_type_str);
                    
                    if (!param_types[j]) {
                        free(param_types);
                        report_error_format(ERROR_ERROR, ERR_INVALID_TYPE, NULL, 
                                           "Invalid parameter type for function %s: %s", 
                                           name, param_type_str);
                        return 0;
                    }
                }
            }
            
            /* Create function type */
            LLVMTypeRef function_type = LLVMFunctionType(return_type, param_types, param_count, 0);
            
            /* Add function declaration to module */
            LLVMValueRef function = LLVMAddFunction(module, name, function_type);
            
            /* Add function to symbol table */
            if (!add_symbol(symbol_table, name, function, function_type, 1, 1)) {
                if (param_types) free(param_types);
                report_error_format(ERROR_ERROR, ERR_DUPLICATE_SYMBOL, NULL, 
                                   "Duplicate function declaration: %s", name);
                return 0;
            }
            
            /* Free parameter types array */
            if (param_types) free(param_types);
        }
    }
    
    return 1;
}

/* Generate code for a program */
int generate_program(ASTNode *program, LLVMModuleRef module, LLVMBuilderRef builder, 
                    SymbolTable *symbol_table) {
    if (!program || !module || !builder || !symbol_table || program->type != NODE_PROGRAM) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid program AST");
        return 0;
    }
    
    /* Iterate through all declarations in the program */
    for (size_t i = 0; i < program->data.program.declaration_count; i++) {
        ASTNode *decl = program->data.program.declarations[i];
        
        if (!decl) continue;
        
        /* Generate code for each declaration */
        switch (decl->type) {
            case NODE_VARIABLE_DECLARATION:
                if (!generate_global_variable_declaration(decl, module, builder, symbol_table)) {
                    return 0;
                }
                break;
                
            case NODE_ARRAY_DECLARATION:
                if (!generate_global_array_declaration(decl, module, builder, symbol_table)) {
                    return 0;
                }
                break;
                
            case NODE_STRUCT_DECLARATION:
                if (!generate_struct_declaration(decl, module, symbol_table)) {
                    return 0;
                }
                break;
                
            case NODE_FUNCTION_DECLARATION:
                if (!generate_function_definition(decl, module, builder, symbol_table)) {
                    return 0;
                }
                break;
            default:
                report_error_format(ERROR_ERROR, ERR_INVALID_AST, NULL, 
                                   "Unexpected declaration type at global scope: %d", 
                                   decl->type);
                return 0;
        }
    }
    
    return 1;
}

/* Generate code for a global variable declaration */
int generate_global_variable_declaration(ASTNode *node, LLVMModuleRef module, 
                                        LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_VARIABLE_DECLARATION) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid variable declaration AST");
        return 0;
    }
    
    const char *name = node->data.variable_declaration.name;
    const char *type_str = node->data.variable_declaration.type;
    ASTNode *initializer = node->data.variable_declaration.initializer;
    
    /* Get variable type */
    LLVMTypeRef type = get_llvm_type(module, type_str);
    if (!type) {
        report_error_format(ERROR_ERROR, ERR_INVALID_TYPE, NULL, 
                           "Invalid type for global variable %s: %s", 
                           name, type_str);
        return 0;
    }
    
    /* Create global variable */
    LLVMValueRef global_var = LLVMAddGlobal(module, type, name);
    
    /* Set initializer if provided, otherwise use zero initializer */
    if (initializer) {
        /* Only constant expressions are allowed as global initializers */
        LLVMValueRef init_val = generate_constant_expression(initializer, module, builder, symbol_table);
        if (!init_val) {
            report_error_format(ERROR_ERROR, ERR_INVALID_OPERATION, NULL, 
                               "Invalid initializer for global variable %s", name);
            return 0;
        }
        
        LLVMSetInitializer(global_var, init_val);
    } else {
        LLVMSetInitializer(global_var, LLVMConstNull(type));
    }
    
    /* Add to symbol table */
    if (!add_symbol(symbol_table, name, global_var, type, 0, 1)) {
        report_error_format(ERROR_ERROR, ERR_DUPLICATE_SYMBOL, NULL, 
                           "Duplicate global variable declaration: %s", name);
        return 0;
    }
    
    return 1;
}

/* Generate code for a global array declaration */
int generate_global_array_declaration(ASTNode *node, LLVMModuleRef module, 
                                     LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_ARRAY_DECLARATION) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid array declaration AST");
        return 0;
    }
    
    const char *name = node->data.array_declaration.name;
    const char *element_type_str = node->data.array_declaration.element_type;
    size_t size = node->data.array_declaration.size;
    ASTNode **initializers = node->data.array_declaration.initializers;
    size_t initializer_count = node->data.array_declaration.initializer_count;
    
    /* Get element type */
    LLVMTypeRef element_type = get_llvm_type(module, element_type_str);
    if (!element_type) {
        report_error_format(ERROR_ERROR, ERR_INVALID_TYPE, NULL, 
                           "Invalid element type for global array %s: %s", 
                           name, element_type_str);
        return 0;
    }
    
    /* Create array type */
    LLVMTypeRef array_type = LLVMArrayType(element_type, size);
    
    /* Create global array */
    LLVMValueRef global_array = LLVMAddGlobal(module, array_type, name);
    
    /* Set initializer if provided, otherwise use zero initializer */
    if (initializers && initializer_count > 0) {
        /* Generate constant initializers */
        LLVMValueRef *init_vals = (LLVMValueRef *)malloc(size * sizeof(LLVMValueRef));
        if (!init_vals) {
            report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, 
                               "Failed to allocate array initializer values");
            return 0;
        }
        
        /* Initialize with zeros first */
        for (size_t i = 0; i < size; i++) {
            init_vals[i] = LLVMConstNull(element_type);
        }
        
        /* Set provided initializers */
        for (size_t i = 0; i < initializer_count && i < size; i++) {
            LLVMValueRef init_val = generate_constant_expression(initializers[i], module, builder, symbol_table);
            if (!init_val) {
                free(init_vals);
                report_error_format(ERROR_ERROR, ERR_INVALID_OPERATION, NULL, 
                                   "Invalid initializer for global array %s at index %zu", 
                                   name, i);
                return 0;
            }
            
            init_vals[i] = init_val;
        }
        
        /* Create constant array */
        LLVMValueRef const_array = LLVMConstArray(element_type, init_vals, size);
        LLVMSetInitializer(global_array, const_array);
        
        free(init_vals);
    } else {
        /* Zero initializer */
        LLVMSetInitializer(global_array, LLVMConstNull(array_type));
    }
    
    /* Add to symbol table */
    if (!add_symbol(symbol_table, name, global_array, array_type, 0, 1)) {
        report_error_format(ERROR_ERROR, ERR_DUPLICATE_SYMBOL, NULL, 
                           "Duplicate global array declaration: %s", name);
        return 0;
    }
    
    return 1;
}

/* Generate code for a struct declaration */
int generate_struct_declaration(ASTNode *node, LLVMModuleRef module, SymbolTable *symbol_table) {
    if (!node || !module || !symbol_table || node->type != NODE_STRUCT_DECLARATION) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid struct declaration AST");
        return 0;
    }
    
    const char *name = node->data.struct_declaration.name;
    StructField *fields = node->data.struct_declaration.fields;
    size_t field_count = node->data.struct_declaration.field_count;
    
    /* Check if struct already exists */
    char struct_name[256];
    snprintf(struct_name, sizeof(struct_name), "struct.%s", name);
    
    if (LLVMGetTypeByName(module, struct_name)) {
        report_error_format(ERROR_ERROR, ERR_DUPLICATE_SYMBOL, NULL, 
                           "Duplicate struct declaration: %s", name);
        return 0;
    }
    
    /* Create struct type */
    LLVMTypeRef struct_type = LLVMStructCreateNamed(LLVMGetGlobalContext(), struct_name);
    
    /* Get field types */
    LLVMTypeRef *field_types = NULL;
    if (field_count > 0) {
        field_types = (LLVMTypeRef *)malloc(field_count * sizeof(LLVMTypeRef));
        if (!field_types) {
            report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, 
                               "Failed to allocate struct field types array");
            return 0;
        }
        
        for (size_t i = 0; i < field_count; i++) {
            field_types[i] = get_llvm_type(module, fields[i].type);
            if (!field_types[i]) {
                free(field_types);
                report_error_format(ERROR_ERROR, ERR_INVALID_TYPE, NULL, 
                                   "Invalid field type for struct %s: %s", 
                                   name, fields[i].type);
                return 0;
            }
        }
    }
    
    /* Set struct body */
    LLVMStructSetBody(struct_type, field_types, field_count, 0);
    
    /* Free field types array */
    if (field_types) free(field_types);
    
    /* Add to symbol table */
    if (!add_symbol(symbol_table, name, NULL, struct_type, 0, 1)) {
        report_error_format(ERROR_ERROR, ERR_DUPLICATE_SYMBOL, NULL, 
                           "Duplicate struct declaration: %s", name);
        return 0;
    }
    
    return 1;
}

/* Generate code for a function definition */
int generate_function_definition(ASTNode *node, LLVMModuleRef module, 
                                LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_FUNCTION_DECLARATION) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid function declaration AST");
        return 0;
    }
    
    const char *name = node->data.function_declaration.name;
    ASTNode *body = node->data.function_declaration.body;
    
    /* Skip if this is just a declaration (no body) */
    if (!body) {
        return 1;
    }
    
    /* Look up function in symbol table */
    SymbolTableEntry *entry = lookup_symbol(symbol_table, name);
    if (!entry || !entry->is_function) {
        report_error_format(ERROR_ERROR, ERR_UNDEFINED_SYMBOL, NULL, 
                           "Undefined function: %s", name);
        return 0;
    }
    
    LLVMValueRef function = entry->value;
    
    /* Create entry basic block */
    LLVMBasicBlockRef entry_block = LLVMAppendBasicBlock(function, "entry");
    LLVMPositionBuilderAtEnd(builder, entry_block);
    
    /* Create new scope for function */
    SymbolTable *function_scope = create_scope(symbol_table);
    if (!function_scope) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, 
                           "Failed to create function scope");
        return 0;
    }
    
    /* Add parameters to symbol table */
    size_t param_count = node->data.function_declaration.param_count;
    for (size_t i = 0; i < param_count; i++) {
        const char *param_name = node->data.function_declaration.params[i].name;
        const char *param_type_str = node->data.function_declaration.params[i].type;
        
        LLVMValueRef param = LLVMGetParam(function, i);
        LLVMTypeRef param_type = get_llvm_type(module, param_type_str);
        
        /* Set parameter name */
        LLVMSetValueName(param, param_name);
        
        /* Create alloca for parameter */
        LLVMValueRef param_alloca = LLVMBuildAlloca(builder, param_type, param_name);
        LLVMBuildStore(builder, param, param_alloca);
        
        /* Add to symbol table */
        if (!add_symbol(function_scope, param_name, param_alloca, param_type, 0, 0)) {
            free_symbol_table(function_scope);
            report_error_format(ERROR_ERROR, ERR_DUPLICATE_SYMBOL, NULL, 
                               "Duplicate parameter name: %s", param_name);
            return 0;
        }
    }
    
    /* Generate code for function body */
    if (!generate_block(body, module, builder, function_scope, function)) {
        free_symbol_table(function_scope);
        return 0;
    }
    
    /* Add implicit return if needed */
    if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(builder))) {
        const char *return_type_str = node->data.function_declaration.return_type;
        if (strcmp(return_type_str, "void") == 0) {
            LLVMBuildRetVoid(builder);
        } else {
            LLVMTypeRef return_type = get_llvm_type(module, return_type_str);
            LLVMBuildRet(builder, LLVMConstNull(return_type));
        }
    }
    
    /* Verify function */
    char *error_message = NULL;
    LLVMBool has_error = LLVMVerifyFunction(function, LLVMPrintMessageAction);
    
    if (has_error) {
        report_error_format(ERROR_ERROR, ERR_LLVM_ERROR, NULL, 
                           "Function verification failed: %s", name);
        free_symbol_table(function_scope);
        return 0;
    }
    
    /* Clean up */
    free_symbol_table(function_scope);
    
    return 1;
}

/* Generate code for a block */
int generate_block(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                  SymbolTable *symbol_table, LLVMValueRef function) {
    if (!node || !module || !builder || !symbol_table || !function || node->type != NODE_BLOCK) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid block AST");
        return 0;
    }
    
    /* Create new scope for block */
    SymbolTable *block_scope = create_scope(symbol_table);
    if (!block_scope) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, 
                           "Failed to create block scope");
        return 0;
    }
    
    /* Generate code for each statement */
    size_t statement_count = node->data.block.statement_count;
    for (size_t i = 0; i < statement_count; i++) {
        ASTNode *stmt = node->data.block.statements[i];
        
        if (!stmt) continue;
        
        /* Skip statements after terminator */
        if (LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(builder))) {
            report_error_simple(ERROR_WARNING, ERR_INVALID_OPERATION, 
                               "Unreachable code detected");
            break;
        }
        
        /* Generate code for statement */
        if (!generate_statement(stmt, module, builder, block_scope, function)) {
            free_symbol_table(block_scope);
            return 0;
        }
    }
    
    /* Clean up */
    free_symbol_table(block_scope);
    
    return 1;
}

/* Generate code for a constant expression (for global initializers) */
LLVMValueRef generate_constant_expression(ASTNode *node, LLVMModuleRef module, 
               LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid constant expression AST");
        return NULL;
    }
    
    switch (node->type) {
        case NODE_INTEGER_LITERAL:
            return create_constant_int(node->data.integer_literal, LLVMInt32Type());
            
        case NODE_FLOAT_LITERAL:
            return create_constant_float(node->data.float_literal);
            
        case NODE_STRING_LITERAL:
            return LLVMConstStringInContext(LLVMGetGlobalContext(), 
                                           node->data.string_literal, 
                                           strlen(node->data.string_literal), 
                                           0);
            
        case NODE_VARIABLE:
            /* Only global variables can be used in constant expressions */
            {
                SymbolTableEntry *entry = lookup_symbol(symbol_table, node->data.variable.name);
                if (!entry || !entry->is_global) {
                    report_error_format(ERROR_ERROR, ERR_INVALID_OPERATION, NULL, 
                                       "Non-global variable in constant expression: %s", 
                                       node->data.variable.name);
                    return NULL;
                }
                
                return entry->value;
            }
            
        case NODE_BINARY_OP:
            /* Only certain binary operations are allowed in constant expressions */
            {
                LLVMValueRef left = generate_constant_expression(node->data.binary_op.left, 
                                                                module, builder, symbol_table);
                LLVMValueRef right = generate_constant_expression(node->data.binary_op.right, 
                                                                 module, builder, symbol_table);
                
                if (!left || !right) {
                    return NULL;
                }
                
                const char *op = node->data.binary_op.op;
                
                /* Integer operations */
                if (LLVMGetTypeKind(LLVMTypeOf(left)) == LLVMIntegerTypeKind && 
                    LLVMGetTypeKind(LLVMTypeOf(right)) == LLVMIntegerTypeKind) {
                    
                    if (strcmp(op, "+") == 0) {
                        return LLVMConstAdd(left, right);
                    } else if (strcmp(op, "-") == 0) {
                        return LLVMConstSub(left, right);
                    } else if (strcmp(op, "*") == 0) {
                        return LLVMConstMul(left, right);
                    } else if (strcmp(op, "/") == 0) {
                        return LLVMConstSDiv(left, right);
                    } else if (strcmp(op, "%") == 0) {
                        return LLVMConstSRem(left, right);
                    } else if (strcmp(op, "&") == 0) {
                        return LLVMConstAnd(left, right);
                    } else if (strcmp(op, "|") == 0) {
                        return LLVMConstOr(left, right);
                    } else if (strcmp(op, "^") == 0) {
                        return LLVMConstXor(left, right);
                    } else if (strcmp(op, "<<") == 0) {
                        return LLVMConstShl(left, right);
                    } else if (strcmp(op, ">>") == 0) {
                        return LLVMConstLShr(left, right);
                    }
                }
                
                /* Float operations */
                if ((LLVMGetTypeKind(LLVMTypeOf(left)) == LLVMFloatTypeKind || 
                     LLVMGetTypeKind(LLVMTypeOf(left)) == LLVMDoubleTypeKind) && 
                    (LLVMGetTypeKind(LLVMTypeOf(right)) == LLVMFloatTypeKind || 
                     LLVMGetTypeKind(LLVMTypeOf(right)) == LLVMDoubleTypeKind)) {
                    
                    if (strcmp(op, "+") == 0) {
                        return LLVMConstFAdd(left, right);
                    } else if (strcmp(op, "-") == 0) {
                        return LLVMConstFSub(left, right);
                    } else if (strcmp(op, "*") == 0) {
                        return LLVMConstFMul(left, right);
                    } else if (strcmp(op, "/") == 0) {
                        return LLVMConstFDiv(left, right);
                    }
                }
                
                report_error_format(ERROR_ERROR, ERR_INVALID_OPERATION, NULL, 
                                   "Invalid operator in constant expression: %s", op);
                return NULL;
            }
            
        case NODE_UNARY_OP:
            /* Only certain unary operations are allowed in constant expressions */
            {
                LLVMValueRef operand = generate_constant_expression(node->data.unary_op.operand, 
                                                                   module, builder, symbol_table);
                
                if (!operand) {
                    return NULL;
                }
                
                const char *op = node->data.unary_op.op;
                
                /* Integer operations */
                if (LLVMGetTypeKind(LLVMTypeOf(operand)) == LLVMIntegerTypeKind) {
                    if (strcmp(op, "-") == 0) {
                        return LLVMConstNeg(operand);
                    } else if (strcmp(op, "~") == 0) {
                        return LLVMConstNot(operand);
                    }
                }
                
                /* Float operations */
                if (LLVMGetTypeKind(LLVMTypeOf(operand)) == LLVMFloatTypeKind || 
                    LLVMGetTypeKind(LLVMTypeOf(operand)) == LLVMDoubleTypeKind) {
                    
                    if (strcmp(op, "-") == 0) {
                        return LLVMConstFNeg(operand);
                    }
                }
                
                report_error_format(ERROR_ERROR, ERR_INVALID_OPERATION, NULL, 
                                   "Invalid unary operator in constant expression: %s", op);
                return NULL;
            }
            
        case NODE_CAST:
            /* Only certain casts are allowed in constant expressions */
            {
                LLVMValueRef expr = generate_constant_expression(node->data.cast.expr, 
                                                                module, builder, symbol_table);
                
                if (!expr) {
                    return NULL;
                }
                
                LLVMTypeRef target_type = get_llvm_type(module, node->data.cast.type);
                if (!target_type) {
                    return NULL;
                }
                
                LLVMTypeRef source_type = LLVMTypeOf(expr);
                
                /* Integer to integer cast */
                if (LLVMGetTypeKind(source_type) == LLVMIntegerTypeKind && 
                    LLVMGetTypeKind(target_type) == LLVMIntegerTypeKind) {
                    
                    unsigned source_width = LLVMGetIntTypeWidth(source_type);
                    unsigned target_width = LLVMGetIntTypeWidth(target_type);
                    
                    if (target_width > source_width) {
                        return LLVMConstSExt(expr, target_type);
                    } else if (target_width < source_width) {
                        return LLVMConstTrunc(expr, target_type);
                    } else {
                        return expr;
                    }
                }
                
                /* Float to float cast */
                if ((LLVMGetTypeKind(source_type) == LLVMFloatTypeKind || 
                     LLVMGetTypeKind(source_type) == LLVMDoubleTypeKind) && 
                    (LLVMGetTypeKind(target_type) == LLVMFloatTypeKind || 
                     LLVMGetTypeKind(target_type) == LLVMDoubleTypeKind)) {
                    
                    if (LLVMGetTypeKind(source_type) == LLVMFloatTypeKind && 
                        LLVMGetTypeKind(target_type) == LLVMDoubleTypeKind) {
                        return LLVMConstFPExt(expr, target_type);
                    } else if (LLVMGetTypeKind(source_type) == LLVMDoubleTypeKind && 
                               LLVMGetTypeKind(target_type) == LLVMFloatTypeKind) {
                        return LLVMConstFPTrunc(expr, target_type);
                    } else {
                        return expr;
                    }
                }
                
                /* Integer to float cast */
                if (LLVMGetTypeKind(source_type) == LLVMIntegerTypeKind && 
                    (LLVMGetTypeKind(target_type) == LLVMFloatTypeKind || 
                     LLVMGetTypeKind(target_type) == LLVMDoubleTypeKind)) {
                    
                    return LLVMConstSIToFP(expr, target_type);
                }
                
                /* Float to integer cast */
                if ((LLVMGetTypeKind(source_type) == LLVMFloatTypeKind || 
                     LLVMGetTypeKind(source_type) == LLVMDoubleTypeKind) && 
                    LLVMGetTypeKind(target_type) == LLVMIntegerTypeKind) {
                    
                    return LLVMConstFPToSI(expr, target_type);
                }
                
                report_error_simple(ERROR_ERROR, ERR_INVALID_CAST, 
                                   "Invalid cast in constant expression");
                return NULL;
            }
            
        default:
            report_error_format(ERROR_ERROR, ERR_INVALID_OPERATION, NULL, 
                               "Invalid node type in constant expression: %d", node->type);
            return NULL;
    }
}

/* Generate code for a statement */
int generate_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                      SymbolTable *symbol_table, LLVMValueRef function) {
    if (!node || !module || !builder || !symbol_table || !function) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid statement AST");
        return 0;
    }
    
    switch (node->type) {
        case NODE_BLOCK:
            return generate_block(node, module, builder, symbol_table, function);
            
        case NODE_VARIABLE_DECLARATION:
            return generate_local_variable_declaration(node, module, builder, symbol_table);
            
        case NODE_ARRAY_DECLARATION:
            return generate_local_array_declaration(node, module, builder, symbol_table);
            
        case NODE_IF_STATEMENT:
            return generate_if_statement(node, module, builder, symbol_table, function);
            
        case NODE_WHILE_STATEMENT:
            return generate_while_statement(node, module, builder, symbol_table, function);
            
        case NODE_FOR_STATEMENT:
            return generate_for_statement(node, module, builder, symbol_table, function);
            
        case NODE_RETURN_STATEMENT:
            return generate_return_statement(node, module, builder, symbol_table, function);
            
        case NODE_BREAK_STATEMENT:
            report_error_simple(ERROR_ERROR, ERR_INVALID_BREAK, 
                               "Break statement not implemented yet");
            return 0;
            
        case NODE_CONTINUE_STATEMENT:
            report_error_simple(ERROR_ERROR, ERR_INVALID_CONTINUE, 
                               "Continue statement not implemented yet");
            return 0;
            
        case NODE_EXPRESSION_STATEMENT:
            return generate_expression_statement(node, module, builder, symbol_table, function);
            
        default:
            report_error_format(ERROR_ERROR, ERR_INVALID_AST, NULL, 
                               "Invalid statement type: %d", node->type);
            return 0;
    }
}

/* Generate code for a local variable declaration */
int generate_local_variable_declaration(ASTNode *node, LLVMModuleRef module, 
                                       LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_VARIABLE_DECLARATION) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid variable declaration AST");
        return 0;
    }
    
    const char *name = node->data.variable_declaration.name;
    const char *type_str = node->data.variable_declaration.type;
    ASTNode *initializer = node->data.variable_declaration.initializer;
    
    /* Get variable type */
    LLVMTypeRef type = get_llvm_type(module, type_str);
    if (!type) {
        report_error_format(ERROR_ERROR, ERR_INVALID_TYPE, NULL, 
                           "Invalid type for local variable %s: %s", 
                           name, type_str);
        return 0;
    }
    
    /* Create alloca for local variable */
    LLVMValueRef var_alloca = LLVMBuildAlloca(builder, type, name);
    
    /* Initialize if provided */
    if (initializer) {
        LLVMValueRef init_val = generate_expression(initializer, module, builder, symbol_table);
        if (!init_val) {
            report_error_format(ERROR_ERROR, ERR_INVALID_OPERATION, NULL, 
                               "Invalid initializer for local variable %s", name);
            return 0;
        }
        
        /* Cast initializer if needed */
        init_val = generate_implicit_cast(init_val, type, module, builder);
        if (!init_val) {
            report_error_format(ERROR_ERROR, ERR_TYPE_MISMATCH, NULL, 
                               "Type mismatch in initializer for local variable %s", name);
            return 0;
        }
        
        LLVMBuildStore(builder, init_val, var_alloca);
    }
    
    /* Add to symbol table */
    if (!add_symbol(symbol_table, name, var_alloca, type, 0, 0)) {
        report_error_format(ERROR_ERROR, ERR_DUPLICATE_SYMBOL, NULL, 
                           "Duplicate local variable declaration: %s", name);
        return 0;
    }
    
    return 1;
}

/* Generate code for a local array declaration */
int generate_local_array_declaration(ASTNode *node, LLVMModuleRef module, 
                                    LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_ARRAY_DECLARATION) {
        report_error_simple(ERROR_ERROR,                                    ERR_INVALID_AST, "Invalid array declaration AST");
        return 0;
    }
    
    const char *name = node->data.array_declaration.name;
    const char *element_type_str = node->data.array_declaration.element_type;
    size_t size = node->data.array_declaration.size;
    ASTNode **initializers = node->data.array_declaration.initializers;
    size_t initializer_count = node->data.array_declaration.initializer_count;
    
    /* Get element type */
    LLVMTypeRef element_type = get_llvm_type(module, element_type_str);
    if (!element_type) {
        report_error_format(ERROR_ERROR, ERR_INVALID_TYPE, NULL, 
                           "Invalid element type for local array %s: %s", 
                           name, element_type_str);
        return 0;
    }
    
    /* Create array type */
    LLVMTypeRef array_type = LLVMArrayType(element_type, size);
    
    /* Create alloca for local array */
    LLVMValueRef array_alloca = LLVMBuildAlloca(builder, array_type, name);
    
    /* Initialize if provided */
    if (initializers && initializer_count > 0) {
        /* Initialize each element */
        for (size_t i = 0; i < initializer_count && i < size; i++) {
            /* Get element pointer */
            LLVMValueRef indices[2];
            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, 0);
            indices[1] = LLVMConstInt(LLVMInt32Type(), i, 0);
            
            LLVMValueRef element_ptr = LLVMBuildGEP(builder, array_alloca, indices, 2, "array_element");
            
            /* Generate initializer value */
            LLVMValueRef init_val = generate_expression(initializers[i], module, builder, symbol_table);
            if (!init_val) {
                report_error_format(ERROR_ERROR, ERR_INVALID_OPERATION, NULL, 
                                   "Invalid initializer for local array %s at index %zu", 
                                   name, i);
                return 0;
            }
            
            /* Cast initializer if needed */
            init_val = generate_implicit_cast(init_val, element_type, module, builder);
            if (!init_val) {
                report_error_format(ERROR_ERROR, ERR_TYPE_MISMATCH, NULL, 
                                   "Type mismatch in initializer for local array %s at index %zu", 
                                   name, i);
                return 0;
            }
            
            LLVMBuildStore(builder, init_val, element_ptr);
        }
    }
    
    /* Add to symbol table */
    if (!add_symbol(symbol_table, name, array_alloca, array_type, 0, 0)) {
        report_error_format(ERROR_ERROR, ERR_DUPLICATE_SYMBOL, NULL, 
                           "Duplicate local array declaration: %s", name);
        return 0;
    }
    
    return 1;
}

/* Generate code for an if statement */
int generate_if_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                         SymbolTable *symbol_table, LLVMValueRef function) {
    if (!node || !module || !builder || !symbol_table || !function || node->type != NODE_IF_STATEMENT) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid if statement AST");
        return 0;
    }
    
    ASTNode *condition = node->data.if_statement.condition;
    ASTNode *then_branch = node->data.if_statement.then_branch;
    ASTNode *else_branch = node->data.if_statement.else_branch;
    
    /* Generate condition */
    LLVMValueRef cond_val = generate_expression(condition, module, builder, symbol_table);
    if (!cond_val) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_CONDITION, "Invalid if condition");
        return 0;
    }
    
    /* Cast condition to boolean if needed */
    cond_val = generate_implicit_cast(cond_val, LLVMInt1Type(), module, builder);
    if (!cond_val) {
        report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Type mismatch in if condition");
        return 0;
    }
    
    /* Create basic blocks */
    LLVMBasicBlockRef then_block = LLVMAppendBasicBlock(function, "then");
    LLVMBasicBlockRef else_block = else_branch ? LLVMAppendBasicBlock(function, "else") : NULL;
    LLVMBasicBlockRef merge_block = LLVMAppendBasicBlock(function, "if_end");
    
    /* Create conditional branch */
    if (else_branch) {
        LLVMBuildCondBr(builder, cond_val, then_block, else_block);
    } else {
        LLVMBuildCondBr(builder, cond_val, then_block, merge_block);
    }
    
    /* Generate then branch */
    LLVMPositionBuilderAtEnd(builder, then_block);
    if (!generate_statement(then_branch, module, builder, symbol_table, function)) {
        return 0;
    }
    
    /* Add branch to merge block if needed */
    if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(builder))) {
        LLVMBuildBr(builder, merge_block);
    }
    
    /* Generate else branch if provided */
    if (else_branch) {
        LLVMPositionBuilderAtEnd(builder, else_block);
        if (!generate_statement(else_branch, module, builder, symbol_table, function)) {
            return 0;
        }
        
        /* Add branch to merge block if needed */
        if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(builder))) {
            LLVMBuildBr(builder, merge_block);
        }
    }
    
    /* Continue at merge block */
    LLVMPositionBuilderAtEnd(builder, merge_block);
    
    return 1;
}

/* Generate code for a while statement */
int generate_while_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                            SymbolTable *symbol_table, LLVMValueRef function) {
    if (!node || !module || !builder || !symbol_table || !function || node->type != NODE_WHILE_STATEMENT) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid while statement AST");
        return 0;
    }
    
    ASTNode *condition = node->data.while_statement.condition;
    ASTNode *body = node->data.while_statement.body;
    
    /* Create basic blocks */
    LLVMBasicBlockRef cond_block = LLVMAppendBasicBlock(function, "while_cond");
    LLVMBasicBlockRef body_block = LLVMAppendBasicBlock(function, "while_body");
    LLVMBasicBlockRef end_block = LLVMAppendBasicBlock(function, "while_end");
    
    /* Branch to condition block */
    LLVMBuildBr(builder, cond_block);
    
    /* Generate condition */
    LLVMPositionBuilderAtEnd(builder, cond_block);
    LLVMValueRef cond_val = generate_expression(condition, module, builder, symbol_table);
    if (!cond_val) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_CONDITION, "Invalid while condition");
        return 0;
    }
    
    /* Cast condition to boolean if needed */
    cond_val = generate_implicit_cast(cond_val, LLVMInt1Type(), module, builder);
    if (!cond_val) {
        report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Type mismatch in while condition");
        return 0;
    }
    
    /* Create conditional branch */
    LLVMBuildCondBr(builder, cond_val, body_block, end_block);
    
    /* Generate body */
    LLVMPositionBuilderAtEnd(builder, body_block);
    if (!generate_statement(body, module, builder, symbol_table, function)) {
        return 0;
    }
    
    /* Add branch back to condition block if needed */
    if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(builder))) {
        LLVMBuildBr(builder, cond_block);
    }
    
    /* Continue at end block */
    LLVMPositionBuilderAtEnd(builder, end_block);
    
    return 1;
}

/* Generate code for a for statement */
int generate_for_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                          SymbolTable *symbol_table, LLVMValueRef function) {
    if (!node || !module || !builder || !symbol_table || !function || node->type != NODE_FOR_STATEMENT) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid for statement AST");
        return 0;
    }
    
    ASTNode *init = node->data.for_statement.init;
    ASTNode *condition = node->data.for_statement.condition;
    ASTNode *update = node->data.for_statement.update;
    ASTNode *body = node->data.for_statement.body;
    
    /* Create new scope for for statement */
    SymbolTable *for_scope = create_scope(symbol_table);
    if (!for_scope) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, 
                           "Failed to create for statement scope");
        return 0;
    }
    
    /* Generate initialization if provided */
    if (init) {
        if (!generate_statement(init, module, builder, for_scope, function)) {
            free_symbol_table(for_scope);
            return 0;
        }
    }
    
    /* Create basic blocks */
    LLVMBasicBlockRef cond_block = LLVMAppendBasicBlock(function, "for_cond");
    LLVMBasicBlockRef body_block = LLVMAppendBasicBlock(function, "for_body");
    LLVMBasicBlockRef update_block = LLVMAppendBasicBlock(function, "for_update");
    LLVMBasicBlockRef end_block = LLVMAppendBasicBlock(function, "for_end");
    
    /* Branch to condition block */
    LLVMBuildBr(builder, cond_block);
    
    /* Generate condition */
    LLVMPositionBuilderAtEnd(builder, cond_block);
    LLVMValueRef cond_val = NULL;
    
    if (condition) {
        cond_val = generate_expression(condition, module, builder, for_scope);
        if (!cond_val) {
            free_symbol_table(for_scope);
            report_error_simple(ERROR_ERROR, ERR_INVALID_CONDITION, "Invalid for condition");
            return 0;
        }
        
        /* Cast condition to boolean if needed */
        cond_val = generate_implicit_cast(cond_val, LLVMInt1Type(), module, builder);
        if (!cond_val) {
            free_symbol_table(for_scope);
            report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Type mismatch in for condition");
            return 0;
        }
    } else {
        /* If no condition is provided, use true */
        cond_val = LLVMConstInt(LLVMInt1Type(), 1, 0);
    }
    
    /* Create conditional branch */
    LLVMBuildCondBr(builder, cond_val, body_block, end_block);
    
    /* Generate body */
    LLVMPositionBuilderAtEnd(builder, body_block);
    if (!generate_statement(body, module, builder, for_scope, function)) {
        free_symbol_table(for_scope);
        return 0;
    }
    
    /* Add branch to update block if needed */
    if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(builder))) {
        LLVMBuildBr(builder, update_block);
    }
    
    /* Generate update */
    LLVMPositionBuilderAtEnd(builder, update_block);
    if (update) {
        if (!generate_statement(update, module, builder, for_scope, function)) {
            free_symbol_table(for_scope);
            return 0;
        }
    }
    
    /* Add branch back to condition block */
    LLVMBuildBr(builder, cond_block);
    
    /* Continue at end block */
    LLVMPositionBuilderAtEnd(builder, end_block);
    
    /* Clean up */
    free_symbol_table(for_scope);
    
    return 1;
}

/* Generate code for a return statement */
int generate_return_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                             SymbolTable *symbol_table, LLVMValueRef function) {
    if (!node || !module || !builder || !symbol_table || !function || node->type != NODE_RETURN_STATEMENT) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid return statement AST");
        return 0;
    }
    
    ASTNode *expr = node->data.return_statement.expr;
    
    /* Get function return type */
    LLVMTypeRef function_type = LLVMGetElementType(LLVMTypeOf(function));
    LLVMTypeRef return_type = LLVMGetReturnType(function_type);
    
    /* Handle void return */
    if (LLVMGetTypeKind(return_type) == LLVMVoidTypeKind) {
        if (expr) {
            report_error_simple(ERROR_ERROR, ERR_INVALID_RETURN, 
                               "Cannot return a value from a void function");
            return 0;
        }
        
        LLVMBuildRetVoid(builder);
        return 1;
    }
    
    /* Handle non-void return */
    if (!expr) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_RETURN, 
                           "Must return a value from a non-void function");
        return 0;
    }
    
    /* Generate return value */
    LLVMValueRef return_val = generate_expression(expr, module, builder, symbol_table);
    if (!return_val) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_RETURN, "Invalid return expression");
        return 0;
    }
    
    /* Cast return value if needed */
    return_val = generate_implicit_cast(return_val, return_type, module, builder);
    if (!return_val) {
        report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Type mismatch in return statement");
        return 0;
    }
    
    LLVMBuildRet(builder, return_val);
    return 1;
}

/* Generate code for an expression statement */
int generate_expression_statement(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                                 SymbolTable *symbol_table, LLVMValueRef function) {
    if (!node || !module || !builder || !symbol_table || !function || node->type != NODE_EXPRESSION_STATEMENT) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid expression statement AST");
        return 0;
    }
    
    ASTNode *expr = node->data.expression_statement.expr;
    
    /* Generate expression (result is discarded) */
    if (expr && !generate_expression(expr, module, builder, symbol_table)) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_EXPRESSION, "Invalid expression in statement");
        return 0;
    }
    
    return 1;
}

/* Generate code for an expression */
LLVMValueRef generate_expression(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                                SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid expression AST");
        return NULL;
    }
    
    switch (node->type) {
        case NODE_INTEGER_LITERAL:
            return LLVMConstInt(LLVMInt32Type(), node->data.integer_literal, 1);
            
        case NODE_FLOAT_LITERAL:
            return LLVMConstReal(LLVMFloatType(), node->data.float_literal);
            
        case NODE_STRING_LITERAL:
            return create_global_string(module, builder, node->data.string_literal, "str");
            
        case NODE_VARIABLE:
            return generate_variable_reference(node, module, builder, symbol_table);
            
        case NODE_ARRAY_ACCESS:
            return generate_array_access(node, module, builder, symbol_table);
            
        case NODE_STRUCT_ACCESS:
            return generate_struct_access(node, module, builder, symbol_table);
            
        case NODE_FUNCTION_CALL:
            return generate_function_call(node, module, builder, symbol_table);
            
        case NODE_ASSIGNMENT:
            return generate_assignment(node, module, builder, symbol_table);
            
        case NODE_BINARY_OP:
            return generate_binary_operation(node, module, builder, symbol_table);
            
        case NODE_UNARY_OP:
            return generate_unary_operation(node, module, builder, symbol_table);
            
        case NODE_TERNARY_OP:
            return generate_ternary_operation(node, module, builder, symbol_table, NULL);
            
        case NODE_CAST:
            return generate_cast_expression(node, module, builder, symbol_table);
            
        default:
            report_error_format(ERROR_ERROR, ERR_INVALID_AST, NULL, 
                               "Invalid expression type: %d", node->type);
            return NULL;
    }
}

/* Generate code for a variable reference */
LLVMValueRef generate_variable_reference(ASTNode *node, LLVMModuleRef module, 
                                        LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_VARIABLE) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid variable reference AST");
        return NULL;
    }
    
    const char *name = node->data.variable.name;
    
    /* Look up variable in symbol table */
    SymbolTableEntry *entry = lookup_symbol(symbol_table, name);
    if (!entry) {
        report_error_format(ERROR_ERROR, ERR_UNDEFINED_SYMBOL, NULL, 
                           "Undefined variable: %s", name);
        return NULL;
    }
    
    /* Get variable value */
    LLVMValueRef var_ptr = entry->value;
    
    /* For global variables, we need to load the value */
    if (entry->is_global) {
        return LLVMBuildLoad(builder, var_ptr, name);
    }
    
    /* For local variables, we need to load the value from the alloca */
    return LLVMBuildLoad(builder, var_ptr, name);
}

/* Generate code for an array access */
LLVMValueRef generate_array_access(ASTNode *node, LLVMModuleRef module, 
                                  LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_ARRAY_ACCESS) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid array access AST");
        return NULL;
    }
    
    ASTNode *array = node->data.array_access.array;
    ASTNode *index = node->data.array_access.index;
    
    /* Generate array reference */
    LLVMValueRef array_ptr = NULL;
    
    if (array->type == NODE_VARIABLE) {
        /* Look up array in symbol table */
        const char *name = array->data.variable.name;
        SymbolTableEntry *entry = lookup_symbol(symbol_table, name);
        
        if (!entry) {
            report_error_format(ERROR_ERROR, ERR_UNDEFINED_SYMBOL, NULL, 
                               "Undefined array: %s", name);
            return NULL;
        }
        
        array_ptr = entry->value;
    } else {
        /* Handle other expressions that evaluate to an array */
        array_ptr = generate_expression(array, module, builder, symbol_table);
        if (!array_ptr) {
            report_error_simple(ERROR_ERROR, ERR_INVALID_EXPRESSION, "Invalid array expression");
            return NULL;
        }
    }
    
    /* Generate index */
    LLVMValueRef index_val = generate_expression(index, module, builder, symbol_table);
    if (!index_val) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_EXPRESSION, "Invalid array index expression");
        return NULL;
    }
    
    /* Cast index to i32 if needed */
    index_val = generate_implicit_cast(index_val, LLVMInt32Type(), module, builder);
    if (!index_val) {
        report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Type mismatch in array index");
        return NULL;
    }
    
    /* Get element pointer */
    LLVMValueRef indices[2];
    indices[0] = LLVMConstInt(LLVMInt32Type(), 0, 0);
    indices[1] = index_val;
    
    LLVMValueRef element_ptr = LLVMBuildGEP(builder, array_ptr, indices, 2, "array_element");
    
    /* Load element value */
    return LLVMBuildLoad(builder, element_ptr, "array_value");
}

/* Generate code for a struct access */
LLVMValueRef generate_struct_access(ASTNode *node, LLVMModuleRef module, 
                                   LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_STRUCT_ACCESS) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid struct access AST");
        return NULL;
    }
    
    ASTNode *structure = node->data.struct_access.structure;
    const char *field = node->data.struct_access.field;
    
    /* Generate struct reference */
    LLVMValueRef struct_ptr = NULL;
    
    if (structure->type == NODE_VARIABLE) {
        /* Look up struct in symbol table */
        const char *name = structure->data.variable.name;
        SymbolTableEntry *entry = lookup_symbol(symbol_table, name);
        
        if (!entry) {
            report_error_format(ERROR_ERROR, ERR_UNDEFINED_SYMBOL, NULL, 
                               "Undefined struct: %s", name);
            return NULL;
        }
        
        struct_ptr = entry->value;
    } else {
        /* Handle other expressions that evaluate to a struct */
        struct_ptr = generate_expression(structure, module, builder, symbol_table);
        if (!struct_ptr) {
            report_error_simple(ERROR_ERROR, ERR_INVALID_EXPRESSION, "Invalid struct expression");
            return NULL;
        }
    }
    
    /* Get struct type */
    LLVMTypeRef struct_type = LLVMGetElementType(LLVMTypeOf(struct_ptr));
    
    /* Check if it's a struct type */
    if (LLVMGetTypeKind(struct_type) != LLVMStructTypeKind) {
        report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Expression is not a struct");
        return NULL;
    }
    
    /* Find field index */
    unsigned field_count = LLVMCountStructElementTypes(struct_type);
    const char *struct_name = LLVMGetStructName(struct_type);
    
    /* Remove "struct." prefix from struct name */
    if (struct_name && strncmp(struct_name, "struct.", 7) == 0) {
        struct_name += 7;
    }
    
    /* Look up struct definition in symbol table */
    SymbolTableEntry *struct_entry = lookup_symbol(symbol_table, struct_name);
    if (!struct_entry) {
        report_error_format(ERROR_ERROR, ERR_UNDEFINED_SYMBOL, NULL, 
                           "Undefined struct type: %s", struct_name);
        return NULL;
    }
    
    /* Find field index */
    int field_index = -1;
    
    /* TODO: Implement field lookup based on struct definition */
    /* For now, we'll just use a simple linear search based on field name */
    for (unsigned i = 0; i < field_count; i++) {
        /* This is a simplification - in a real implementation, we would need to
           store field names in the struct definition and look them up */
        if (i == atoi(field)) {
            field_index = i;
            break;
        }
    }
    
    if (field_index == -1) {
        report_error_format(ERROR_ERROR, ERR_UNDEFINED_SYMBOL, NULL, 
                           "Undefined field '%s' in struct '%s'", field, struct_name);
        return NULL;
    }
    
    /* Get field pointer */
    LLVMValueRef indices[2];
    indices[0] = LLVMConstInt(LLVMInt32Type(), 0, 0);
    indices[1] = LLVMConstInt(LLVMInt32Type(), field_index, 0);
    
    LLVMValueRef field_ptr = LLVMBuildGEP(builder, struct_ptr, indices, 2, "struct_field");
    
    /* Load field value */
    return LLVMBuildLoad(builder, field_ptr, field);
}

/* Generate code for a function call */
LLVMValueRef generate_function_call(ASTNode *node, LLVMModuleRef module, 
                                   LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_FUNCTION_CALL) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid function call AST");
        return NULL;
    }
    
    const char *name = node->data.function_call.name;
    ASTNode **args = node->data.function_call.args;
    size_t arg_count = node->data.function_call.arg_count;
    
    /* Look up function in symbol table */
    SymbolTableEntry *entry = lookup_symbol(symbol_table, name);
    if (!entry || !entry->is_function) {
        report_error_format(ERROR_ERROR, ERR_UNDEFINED_SYMBOL, NULL, 
                           "Undefined function: %s", name);
        return NULL;
    }
    
    LLVMValueRef function = entry->value;
    LLVMTypeRef function_type = entry->type;
    
    /* Check argument count */
    unsigned param_count = LLVMCountParamTypes(function_type);
    if (param_count != arg_count && !LLVMIsFunctionVarArg(function_type)) {
        report_error_format(ERROR_ERROR, ERR_INVALID_ARGUMENTS, NULL, 
                           "Wrong number of arguments for function %s: expected %u, got %zu", 
                           name, param_count, arg_count);
        return NULL;
    }
    
    /* Generate arguments */
    LLVMValueRef *arg_values = NULL;
    if (arg_count > 0) {
        arg_values = (LLVMValueRef *)malloc(arg_count * sizeof(LLVMValueRef));
        if (!arg_values) {
            report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, 
                               "Failed to allocate argument values array");
            return NULL;
        }
        
        /* Get parameter types */
        LLVMTypeRef *param_types = NULL;
        if (param_count > 0) {
            param_types = (LLVMTypeRef *)malloc(param_count * sizeof(LLVMTypeRef));
            if (!param_types) {
                free(arg_values);
                report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, 
                                   "Failed to allocate parameter types array");
                return NULL;
            }
            
            LLVMGetParamTypes(function_type, param_types);
        }
        
        /* Generate and cast arguments */
        for (size_t i = 0; i < arg_count; i++) {
            arg_values[i] = generate_expression(args[i], module, builder, symbol_table);
            if (!arg_values[i]) {
                if (param_types) free(param_types);
                free(arg_values);
                report_error_format(ERROR_ERROR, ERR_INVALID_EXPRESSION, NULL, 
                                   "Invalid argument %zu for function %s", i + 1, name);
                return NULL;
            }
            
            /* Cast argument if needed and if not a vararg function or within param count */
            if (i < param_count) {
                arg_values[i] = generate_implicit_cast(arg_values[i], param_types[i], module, builder);
                if (!arg_values[i]) {
                    if (param_types) free(param_types);
                    free(arg_values);
                    report_error_format(ERROR_ERROR, ERR_TYPE_MISMATCH, NULL,
                          "Type mismatch in argument %zu for function %s", 
                          i + 1, name);
                    return NULL;
                }
            }
        }
        
        if (param_types) free(param_types);
    }
    
    /* Call function */
    LLVMValueRef call = LLVMBuildCall(builder, function, arg_values, arg_count, 
                                     LLVMGetReturnType(function_type) == LLVMVoidType() ? "" : "call");
    
    /* Free argument values array */
    if (arg_values) free(arg_values);
    
    return call;
}

/* Generate code for an assignment */
LLVMValueRef generate_assignment(ASTNode *node, LLVMModuleRef module, 
                                LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_ASSIGNMENT) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid assignment AST");
        return NULL;
    }
    
    ASTNode *lhs = node->data.assignment.lhs;
    ASTNode *rhs = node->data.assignment.rhs;
    
    /* Generate right-hand side expression */
    LLVMValueRef rhs_val = generate_expression(rhs, module, builder, symbol_table);
    if (!rhs_val) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_EXPRESSION, "Invalid right-hand side expression");
        return NULL;
    }
    
    /* Handle different left-hand side expressions */
    if (lhs->type == NODE_VARIABLE) {
        /* Variable assignment */
        const char *name = lhs->data.variable.name;
        
        /* Look up variable in symbol table */
        SymbolTableEntry *entry = lookup_symbol(symbol_table, name);
        if (!entry) {
            report_error_format(ERROR_ERROR, ERR_UNDEFINED_SYMBOL, NULL, 
                               "Undefined variable: %s", name);
            return NULL;
        }
        
        /* Get variable pointer */
        LLVMValueRef var_ptr = entry->value;
        
        /* Cast right-hand side if needed */
        LLVMTypeRef var_type = LLVMGetElementType(LLVMTypeOf(var_ptr));
        rhs_val = generate_implicit_cast(rhs_val, var_type, module, builder);
        if (!rhs_val) {
            report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Type mismatch in assignment");
            return NULL;
        }
        
        /* Store value */
        LLVMBuildStore(builder, rhs_val, var_ptr);
        
        /* Return the assigned value */
        return rhs_val;
    } else if (lhs->type == NODE_ARRAY_ACCESS) {
        /* Array element assignment */
        ASTNode *array = lhs->data.array_access.array;
        ASTNode *index = lhs->data.array_access.index;
        
        /* Generate array reference */
        LLVMValueRef array_ptr = NULL;
        
        if (array->type == NODE_VARIABLE) {
            /* Look up array in symbol table */
            const char *name = array->data.variable.name;
            SymbolTableEntry *entry = lookup_symbol(symbol_table, name);
            
            if (!entry) {
                report_error_format(ERROR_ERROR, ERR_UNDEFINED_SYMBOL, NULL, 
                                   "Undefined array: %s", name);
                return NULL;
            }
            
            array_ptr = entry->value;
        } else {
            /* Handle other expressions that evaluate to an array */
            array_ptr = generate_expression(array, module, builder, symbol_table);
            if (!array_ptr) {
                report_error_simple(ERROR_ERROR, ERR_INVALID_EXPRESSION, "Invalid array expression");
                return NULL;
            }
        }
        
        /* Generate index */
        LLVMValueRef index_val = generate_expression(index, module, builder, symbol_table);
        if (!index_val) {
            report_error_simple(ERROR_ERROR, ERR_INVALID_EXPRESSION, "Invalid array index expression");
            return NULL;
        }
        
        /* Cast index to i32 if needed */
        index_val = generate_implicit_cast(index_val, LLVMInt32Type(), module, builder);
        if (!index_val) {
            report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Type mismatch in array index");
            return NULL;
        }
        
        /* Get element pointer */
        LLVMValueRef indices[2];
        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, 0);
        indices[1] = index_val;
        
        LLVMValueRef element_ptr = LLVMBuildGEP(builder, array_ptr, indices, 2, "array_element");
        
        /* Cast right-hand side if needed */
        LLVMTypeRef element_type = LLVMGetElementType(LLVMTypeOf(element_ptr));
        rhs_val = generate_implicit_cast(rhs_val, element_type, module, builder);
        if (!rhs_val) {
            report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Type mismatch in array assignment");
            return NULL;
        }
        
        /* Store value */
        LLVMBuildStore(builder, rhs_val, element_ptr);
        
        /* Return the assigned value */
        return rhs_val;
    } else if (lhs->type == NODE_STRUCT_ACCESS) {
        /* Struct field assignment */
        ASTNode *structure = lhs->data.struct_access.structure;
        const char *field = lhs->data.struct_access.field;
        
        /* Generate struct reference */
        LLVMValueRef struct_ptr = NULL;
        
        if (structure->type == NODE_VARIABLE) {
            /* Look up struct in symbol table */
            const char *name = structure->data.variable.name;
            SymbolTableEntry *entry = lookup_symbol(symbol_table, name);
            
            if (!entry) {
                report_error_format(ERROR_ERROR, ERR_UNDEFINED_SYMBOL, NULL, 
                                   "Undefined struct: %s", name);
                return NULL;
            }
            
            struct_ptr = entry->value;
        } else {
            /* Handle other expressions that evaluate to a struct */
            struct_ptr = generate_expression(structure, module, builder, symbol_table);
            if (!struct_ptr) {
                report_error_simple(ERROR_ERROR, ERR_INVALID_EXPRESSION, "Invalid struct expression");
                return NULL;
            }
        }
        
        /* Get struct type */
        LLVMTypeRef struct_type = LLVMGetElementType(LLVMTypeOf(struct_ptr));
        
        /* Check if it's a struct type */
        if (LLVMGetTypeKind(struct_type) != LLVMStructTypeKind) {
            report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Expression is not a struct");
            return NULL;
        }
        
        /* Find field index */
        unsigned field_count = LLVMCountStructElementTypes(struct_type);
        const char *struct_name = LLVMGetStructName(struct_type);
        
        /* Remove "struct." prefix from struct name */
        if (struct_name && strncmp(struct_name, "struct.", 7) == 0) {
            struct_name += 7;
        }
        
        /* Look up struct definition in symbol table */
        SymbolTableEntry *struct_entry = lookup_symbol(symbol_table, struct_name);
        if (!struct_entry) {
            report_error_format(ERROR_ERROR, ERR_UNDEFINED_SYMBOL, NULL, 
                               "Undefined struct type: %s", struct_name);
            return NULL;
        }
        
        /* Find field index */
        int field_index = -1;
        
        /* TODO: Implement field lookup based on struct definition */
        /* For now, we'll just use a simple linear search based on field name */
        for (unsigned i = 0; i < field_count; i++) {
            /* This is a simplification - in a real implementation, we would need to
               store field names in the struct definition and look them up */
            if (i == atoi(field)) {
                field_index = i;
                break;
            }
        }
        
        if (field_index == -1) {
            report_error_format(ERROR_ERROR, ERR_UNDEFINED_SYMBOL, NULL, 
                               "Undefined field '%s' in struct '%s'", field, struct_name);
            return NULL;
        }
        
        /* Get field pointer */
        LLVMValueRef indices[2];
        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, 0);
        indices[1] = LLVMConstInt(LLVMInt32Type(), field_index, 0);
        
        LLVMValueRef field_ptr = LLVMBuildGEP(builder, struct_ptr, indices, 2, "struct_field");
        
        /* Cast right-hand side if needed */
        LLVMTypeRef field_type = LLVMGetElementType(LLVMTypeOf(field_ptr));
        rhs_val = generate_implicit_cast(rhs_val, field_type, module, builder);
        if (!rhs_val) {
            report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Type mismatch in struct field assignment");
            return NULL;
        }
        
        /* Store value */
        LLVMBuildStore(builder, rhs_val, field_ptr);
        
        /* Return the assigned value */
        return rhs_val;
    } else {
        report_error_simple(ERROR_ERROR, ERR_INVALID_LVALUE, "Invalid left-hand side in assignment");
        return NULL;
    }
}

/* Generate code for a binary operation */
LLVMValueRef generate_binary_operation(ASTNode *node, LLVMModuleRef module, 
                                      LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_BINARY_OP) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid binary operation AST");
        return NULL;
    }
    
    ASTNode *left = node->data.binary_op.left;
    ASTNode *right = node->data.binary_op.right;
    const char *op = node->data.binary_op.op;
    
    /* Generate operands */
    LLVMValueRef left_val = generate_expression(left, module, builder, symbol_table);
    LLVMValueRef right_val = generate_expression(right, module, builder, symbol_table);
    
    if (!left_val || !right_val) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_EXPRESSION, "Invalid operand in binary operation");
        return NULL;
    }
    
    /* Get operand types */
    LLVMTypeRef left_type = LLVMTypeOf(left_val);
    LLVMTypeRef right_type = LLVMTypeOf(right_val);
    
    /* Perform type promotion */
    LLVMTypeRef result_type = promote_types(left_type, right_type);
    if (!result_type) {
        report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Incompatible types in binary operation");
        return NULL;
    }
    
    /* Cast operands if needed */
    left_val = generate_implicit_cast(left_val, result_type, module, builder);
    right_val = generate_implicit_cast(right_val, result_type, module, builder);
    
    if (!left_val || !right_val) {
        report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Type mismatch in binary operation");
        return NULL;
    }
    
    /* Perform operation based on type */
    LLVMTypeKind type_kind = LLVMGetTypeKind(result_type);
    
    /* Integer operations */
    if (type_kind == LLVMIntegerTypeKind) {
        if (strcmp(op, "+") == 0) {
            return LLVMBuildAdd(builder, left_val, right_val, "add");
        } else if (strcmp(op, "-") == 0) {
            return LLVMBuildSub(builder, left_val, right_val, "sub");
        } else if (strcmp(op, "*") == 0) {
            return LLVMBuildMul(builder, left_val, right_val, "mul");
        } else if (strcmp(op, "/") == 0) {
            return LLVMBuildSDiv(builder, left_val, right_val, "div");
        } else if (strcmp(op, "%") == 0) {
            return LLVMBuildSRem(builder, left_val, right_val, "rem");
        } else if (strcmp(op, "&") == 0) {
            return LLVMBuildAnd(builder, left_val, right_val, "and");
        } else if (strcmp(op, "|") == 0) {
            return LLVMBuildOr(builder, left_val, right_val, "or");
        } else if (strcmp(op, "^") == 0) {
            return LLVMBuildXor(builder, left_val, right_val, "xor");
        } else if (strcmp(op, "<<") == 0) {
            return LLVMBuildShl(builder, left_val, right_val, "shl");
        } else if (strcmp(op, ">>") == 0) {
            return LLVMBuildLShr(builder, left_val, right_val, "shr");
        } else if (strcmp(op, "==") == 0) {
            return LLVMBuildICmp(builder, LLVMIntEQ, left_val, right_val, "eq");
        } else if (strcmp(op, "!=") == 0) {
            return LLVMBuildICmp(builder, LLVMIntNE, left_val, right_val, "ne");
        } else if (strcmp(op, "<") == 0) {
            return LLVMBuildICmp(builder, LLVMIntSLT, left_val, right_val, "lt");
        } else if (strcmp(op, "<=") == 0) {
            return LLVMBuildICmp(builder, LLVMIntSLE, left_val, right_val, "le");
        } else if (strcmp(op, ">") == 0) {
            return LLVMBuildICmp(builder, LLVMIntSGT, left_val, right_val, "gt");
        } else if(strcmp(op, ">=") == 0) {
            return LLVMBuildICmp(builder, LLVMIntSGE, left_val, right_val, "ge");
        } else if (strcmp(op, "&&") == 0) {
            /* Logical AND with short-circuit evaluation */
            LLVMBasicBlockRef current_block = LLVMGetInsertBlock(builder);
            LLVMValueRef function = LLVMGetBasicBlockParent(current_block);
            
            LLVMBasicBlockRef right_block = LLVMAppendBasicBlock(function, "and_right");
            LLVMBasicBlockRef end_block = LLVMAppendBasicBlock(function, "and_end");
            
            /* Convert left value to boolean */
            left_val = LLVMBuildICmp(builder, LLVMIntNE, left_val, 
                                    LLVMConstInt(result_type, 0, 0), "left_bool");
            
            /* Conditional branch */
            LLVMBuildCondBr(builder, left_val, right_block, end_block);
            
            /* Right operand evaluation */
            LLVMPositionBuilderAtEnd(builder, right_block);
            right_val = LLVMBuildICmp(builder, LLVMIntNE, right_val, 
                                     LLVMConstInt(result_type, 0, 0), "right_bool");
            LLVMBuildBr(builder, end_block);
            
            /* Phi node for result */
            LLVMPositionBuilderAtEnd(builder, end_block);
            LLVMValueRef phi = LLVMBuildPhi(builder, LLVMInt1Type(), "and_result");
            
            LLVMValueRef values[2] = { LLVMConstInt(LLVMInt1Type(), 0, 0), right_val };
            LLVMBasicBlockRef blocks[2] = { current_block, right_block };
            LLVMAddIncoming(phi, values, blocks, 2);
            
            return phi;
        } else if (strcmp(op, "||") == 0) {
            /* Logical OR with short-circuit evaluation */
            LLVMBasicBlockRef current_block = LLVMGetInsertBlock(builder);
            LLVMValueRef function = LLVMGetBasicBlockParent(current_block);
            
            LLVMBasicBlockRef right_block = LLVMAppendBasicBlock(function, "or_right");
            LLVMBasicBlockRef end_block = LLVMAppendBasicBlock(function, "or_end");
            
            /* Convert left value to boolean */
            left_val = LLVMBuildICmp(builder, LLVMIntNE, left_val, 
                                    LLVMConstInt(result_type, 0, 0), "left_bool");
            
            /* Conditional branch */
            LLVMBuildCondBr(builder, left_val, end_block, right_block);
            
            /* Right operand evaluation */
            LLVMPositionBuilderAtEnd(builder, right_block);
            right_val = LLVMBuildICmp(builder, LLVMIntNE, right_val, 
                                     LLVMConstInt(result_type, 0, 0), "right_bool");
            LLVMBuildBr(builder, end_block);
            
            /* Phi node for result */
            LLVMPositionBuilderAtEnd(builder, end_block);
            LLVMValueRef phi = LLVMBuildPhi(builder, LLVMInt1Type(), "or_result");
            
            LLVMValueRef values[2] = { LLVMConstInt(LLVMInt1Type(), 1, 0), right_val };
            LLVMBasicBlockRef blocks[2] = { current_block, right_block };
            LLVMAddIncoming(phi, values, blocks, 2);
            
            return phi;
        }
    }
    
    /* Float operations */
    if (type_kind == LLVMFloatTypeKind || type_kind == LLVMDoubleTypeKind) {
        if (strcmp(op, "+") == 0) {
            return LLVMBuildFAdd(builder, left_val, right_val, "fadd");
        } else if (strcmp(op, "-") == 0) {
            return LLVMBuildFSub(builder, left_val, right_val, "fsub");
        } else if (strcmp(op, "*") == 0) {
            return LLVMBuildFMul(builder, left_val, right_val, "fmul");
        } else if (strcmp(op, "/") == 0) {
            return LLVMBuildFDiv(builder, left_val, right_val, "fdiv");
        } else if (strcmp(op, "==") == 0) {
            return LLVMBuildFCmp(builder, LLVMRealOEQ, left_val, right_val, "feq");
        } else if (strcmp(op, "!=") == 0) {
            return LLVMBuildFCmp(builder, LLVMRealONE, left_val, right_val, "fne");
        } else if (strcmp(op, "<") == 0) {
            return LLVMBuildFCmp(builder, LLVMRealOLT, left_val, right_val, "flt");
        } else if (strcmp(op, "<=") == 0) {
            return LLVMBuildFCmp(builder, LLVMRealOLE, left_val, right_val, "fle");
        } else if (strcmp(op, ">") == 0) {
            return LLVMBuildFCmp(builder, LLVMRealOGT, left_val, right_val, "fgt");
        } else if (strcmp(op, ">=") == 0) {
            return LLVMBuildFCmp(builder, LLVMRealOGE, left_val, right_val, "fge");
        }
    }
    
    report_error_format(ERROR_ERROR, ERR_INVALID_OPERATION, NULL, 
                       "Invalid binary operator: %s", op);
    return NULL;
}

/* Generate code for a unary operation */
LLVMValueRef generate_unary_operation(ASTNode *node, LLVMModuleRef module, 
                                     LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_UNARY_OP) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid unary operation AST");
        return NULL;
    }
    
    ASTNode *operand = node->data.unary_op.operand;
    const char *op = node->data.unary_op.op;
    
    /* Generate operand */
    LLVMValueRef operand_val = generate_expression(operand, module, builder, symbol_table);
    if (!operand_val) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_EXPRESSION, "Invalid operand in unary operation");
        return NULL;
    }
    
    /* Get operand type */
    LLVMTypeRef operand_type = LLVMTypeOf(operand_val);
    LLVMTypeKind type_kind = LLVMGetTypeKind(operand_type);
    
    /* Perform operation based on type */
    if (type_kind == LLVMIntegerTypeKind) {
        if (strcmp(op, "-") == 0) {
            return LLVMBuildNeg(builder, operand_val, "neg");
        } else if (strcmp(op, "~") == 0) {
            return LLVMBuildNot(builder, operand_val, "not");
        } else if (strcmp(op, "!") == 0) {
            /* Convert to boolean first */
            LLVMValueRef bool_val = LLVMBuildICmp(builder, LLVMIntNE, operand_val, 
                                                 LLVMConstInt(operand_type, 0, 0), "bool_val");
            return LLVMBuildNot(builder, bool_val, "logical_not");
        }
    } else if (type_kind == LLVMFloatTypeKind || type_kind == LLVMDoubleTypeKind) {
        if (strcmp(op, "-") == 0) {
            return LLVMBuildFNeg(builder, operand_val, "fneg");
        } else if (strcmp(op, "!") == 0) {
            /* Convert to boolean first */
            LLVMValueRef bool_val = LLVMBuildFCmp(builder, LLVMRealONE, operand_val, 
                                                 LLVMConstReal(operand_type, 0.0), "float_bool");
            return LLVMBuildNot(builder, bool_val, "logical_not");
        }
    }
    
    report_error_format(ERROR_ERROR, ERR_INVALID_OPERATION, NULL, 
                       "Invalid unary operator: %s", op);
    return NULL;
}

/* Generate code for a ternary operation */
LLVMValueRef generate_ternary_operation(ASTNode *node, LLVMModuleRef module, 
                                       LLVMBuilderRef builder, SymbolTable *symbol_table,
                                       LLVMTypeRef target_type) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_TERNARY_OP) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid ternary operation AST");
        return NULL;
    }
    
    ASTNode *condition = node->data.ternary_op.condition;
    ASTNode *then_expr = node->data.ternary_op.then_expr;
    ASTNode *else_expr = node->data.ternary_op.else_expr;
    
    /* Generate condition */
    LLVMValueRef cond_val = generate_expression(condition, module, builder, symbol_table);
    if (!cond_val) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_CONDITION, "Invalid condition in ternary operation");
        return NULL;
    }
    
    /* Cast condition to boolean if needed */
    cond_val = generate_implicit_cast(cond_val, LLVMInt1Type(), module, builder);
    if (!cond_val) {
        report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Type mismatch in ternary condition");
        return NULL;
    }
    
    /* Create basic blocks */
    LLVMBasicBlockRef current_block = LLVMGetInsertBlock(builder);
    LLVMValueRef function = LLVMGetBasicBlockParent(current_block);
    
    LLVMBasicBlockRef then_block = LLVMAppendBasicBlock(function, "ternary_then");
    LLVMBasicBlockRef else_block = LLVMAppendBasicBlock(function, "ternary_else");
    LLVMBasicBlockRef merge_block = LLVMAppendBasicBlock(function, "ternary_end");
    
    /* Create conditional branch */
    LLVMBuildCondBr(builder, cond_val, then_block, else_block);
    
    /* Generate then expression */
    LLVMPositionBuilderAtEnd(builder, then_block);
    LLVMValueRef then_val = generate_expression(then_expr, module, builder, symbol_table);
    if (!then_val) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_EXPRESSION, "Invalid then expression in ternary operation");
        return NULL;
    }
    
    /* Remember the block after generating the then expression */
    LLVMBasicBlockRef then_end_block = LLVMGetInsertBlock(builder);
    
    /* Branch to merge block */
    LLVMBuildBr(builder, merge_block);
    
    /* Generate else expression */
    LLVMPositionBuilderAtEnd(builder, else_block);
    LLVMValueRef else_val = generate_expression(else_expr, module, builder, symbol_table);
    if (!else_val) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_EXPRESSION, "Invalid else expression in ternary operation");
        return NULL;
    }
    
    /* Remember the block after generating the else expression */
    LLVMBasicBlockRef else_end_block = LLVMGetInsertBlock(builder);
    
    /* Branch to merge block */
    LLVMBuildBr(builder, merge_block);
    
    /* Continue at merge block */
    LLVMPositionBuilderAtEnd(builder, merge_block);
    
    /* Determine result type */
    LLVMTypeRef result_type = target_type;
    if (!result_type) {
        result_type = promote_types(LLVMTypeOf(then_val), LLVMTypeOf(else_val));
        if (!result_type) {
            report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Incompatible types in ternary operation");
            return NULL;
        }
    }
    
    /* Cast operands if needed */
    then_val = generate_implicit_cast(then_val, result_type, module, builder);
    else_val = generate_implicit_cast(else_val, result_type, module, builder);
    
    if (!then_val || !else_val) {
        report_error_simple(ERROR_ERROR, ERR_TYPE_MISMATCH, "Type mismatch in ternary operation");
        return NULL;
    }
    
    /* Create phi node for result */
    LLVMValueRef phi = LLVMBuildPhi(builder, result_type, "ternary_result");
    
    LLVMValueRef values[2] = { then_val, else_val };
    LLVMBasicBlockRef blocks[2] = { then_end_block, else_end_block };
    LLVMAddIncoming(phi, values, blocks, 2);
    
    return phi;
}

/* Generate code for a cast expression */
LLVMValueRef generate_cast_expression(ASTNode *node, LLVMModuleRef module, 
                                     LLVMBuilderRef builder, SymbolTable *symbol_table) {
    if (!node || !module || !builder || !symbol_table || node->type != NODE_CAST) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid cast expression AST");
        return NULL;
    }
    
    ASTNode *expr = node->data.cast.expr;
    const char *type_str = node->data.cast.type;
    
    /* Generate expression */
    LLVMValueRef expr_val = generate_expression(expr, module, builder, symbol_table);
    if (!expr_val) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_EXPRESSION, "Invalid expression in cast");
        return NULL;
    }
    
    /* Get target type */
    LLVMTypeRef target_type = get_llvm_type(module, type_str);
    if (!target_type) {
        report_error_format(ERROR_ERROR, ERR_INVALID_TYPE, NULL, 
                           "Invalid target type for cast: %s", type_str);
        return NULL;
    }
    
    /* Perform cast */
    return generate_explicit_cast(expr_val, target_type, module, builder);
}

/* Generate code for a block */
int generate_block(ASTNode *node, LLVMModuleRef module, LLVMBuilderRef builder, 
                  SymbolTable *symbol_table, LLVMValueRef function) {
    if (!node || !module || !builder || !symbol_table || !function || node->type != NODE_BLOCK) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_AST, "Invalid block AST");
        return 0;
    }
    
    ASTNode **statements = node->data.block.statements;
    size_t statement_count = node->data.block.statement_count;
    
    /* Create new scope for block */
    SymbolTable *block_scope = create_scope(symbol_table);
    if (!block_scope) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to create block scope");
        return 0;
    }
    
    /* Generate code for each statement */
    for (size_t i = 0; i < statement_count; i++) {
        if (!generate_statement(statements[i], module, builder, block_scope, function)) {
            free_symbol_table(block_scope);
            return 0;
        }
        
        /* Check if we've already generated a terminator (e.g., return) */
        if (LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(builder))) {
            break;
        }
    }
    
    /* Clean up */
    free_symbol_table(block_scope);
    
    return 1;
}

/* Generate an implicit cast */
LLVMValueRef generate_implicit_cast(LLVMValueRef value, LLVMTypeRef target_type, 
                                   LLVMModuleRef module, LLVMBuilderRef builder) {
    if (!value || !target_type || !module || !builder) {
        return NULL;
    }
    
    LLVMTypeRef source_type = LLVMTypeOf(value);
    
    /* No cast needed if types are the same */
    if (LLVMTypeOf(value) == target_type) {
        return value;
    }
    
    LLVMTypeKind source_kind = LLVMGetTypeKind(source_type);
    LLVMTypeKind target_kind = LLVMGetTypeKind(target_type);
    
    /* Integer to integer cast */
    if (source_kind == LLVMIntegerTypeKind && target_kind == LLVMIntegerTypeKind) {
        unsigned source_width = LLVMGetIntTypeWidth(source_type);
        unsigned target_width = LLVMGetIntTypeWidth(target_type);
        
        if (target_width > source_width) {
            /* Sign extend */
            return LLVMBuildSExt(builder, value, target_type, "sext");
        } else if (target_width < source_width) {
            /* Truncate */
            return LLVMBuildTrunc(builder, value, target_type, "trunc");
        }
    }
    
    /* Integer to float cast */
    if (source_kind == LLVMIntegerTypeKind && 
        (target_kind == LLVMFloatTypeKind || target_kind == LLVMDoubleTypeKind)) {
        
        return LLVMBuildSIToFP(builder, value, target_type, "sitofp");
    }
    
    /* Float to integer cast */
    if ((source_kind == LLVMFloatTypeKind || source_kind == LLVMDoubleTypeKind) && 
        target_kind == LLVMIntegerTypeKind) {
        
        return LLVMBuildFPToSI(builder, value, target_type, "fptosi");
    }
    
    /* Float to float cast */
    if ((source_kind == LLVMFloatTypeKind || source_kind == LLVMDoubleTypeKind) && 
        (target_kind == LLVMFloatTypeKind || target_kind == LLVMDoubleTypeKind)) {
        
        if (source_kind == LLVMFloatTypeKind && target_kind == LLVMDoubleTypeKind) {
            /* Float to double */
            return LLVMBuildFPExt(builder, value, target_type, "fpext");
        } else if (source_kind == LLVMDoubleTypeKind && target_kind == LLVMFloatTypeKind) {
            /* Double to float */
            return LLVMBuildFPTrunc(builder, value, target_type, "fptrunc");
        }
    }
    
    /* Boolean to integer cast */
    if (source_kind == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(source_type) == 1 && 
        target_kind == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(target_type) > 1) {
        
        return LLVMBuildZExt(builder, value, target_type, "zext");
    }
    
    /* Integer to boolean cast */
    if (source_kind == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(source_type) > 1 && 
        target_kind == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(target_type) == 1) {
        
        return LLVMBuildICmp(builder, LLVMIntNE, value, 
                            LLVMConstInt(source_type, 0, 0), "tobool");
    }
    
    /* Float to boolean cast */
    if ((source_kind == LLVMFloatTypeKind || source_kind == LLVMDoubleTypeKind) && 
        target_kind == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(target_type) == 1) {
        
        return LLVMBuildFCmp(builder, LLVMRealONE, value, 
                            LLVMConstReal(source_type, 0.0), "ftobool");
    }
    
    /* Pointer to boolean cast */
    if (source_kind == LLVMPointerTypeKind && 
        target_kind == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(target_type) == 1) {
        
        LLVMValueRef null_ptr = LLVMConstNull(source_type);
        return LLVMBuildICmp(builder, LLVMIntNE, value, null_ptr, "ptobool");
    }
    
    /* Integer to pointer cast */
    if (source_kind == LLVMIntegerTypeKind && target_kind == LLVMPointerTypeKind) {
        return LLVMBuildIntToPtr(builder, value, target_type, "inttoptr");
    }
    
    /* Pointer to integer cast */
    if (source_kind == LLVMPointerTypeKind && target_kind == LLVMIntegerTypeKind) {
        return LLVMBuildPtrToInt(builder, value, target_type, "ptrtoint");
    }
    
    /* Pointer to pointer cast */
    if (source_kind == LLVMPointerTypeKind && target_kind == LLVMPointerTypeKind) {
        return LLVMBuildBitCast(builder, value, target_type, "ptrcast");
    }
    
    return NULL;
}

/* Generate an explicit cast */
LLVMValueRef generate_explicit_cast(LLVMValueRef value, LLVMTypeRef target_type, 
                                   LLVMModuleRef module, LLVMBuilderRef builder) {
    if (!value || !target_type || !module || !builder) {
        return NULL;
    }
    
    /* Try implicit cast first */
    LLVMValueRef result = generate_implicit_cast(value, target_type, module, builder);
    if (result) {
        return result;
    }
    
    /* If implicit cast failed, try more aggressive explicit casts */
    LLVMTypeRef source_type = LLVMTypeOf(value);
    LLVMTypeKind source_kind = LLVMGetTypeKind(source_type);
    LLVMTypeKind target_kind = LLVMGetTypeKind(target_type);
    
    /* Integer to integer cast (unsigned) */
    if (source_kind == LLVMIntegerTypeKind && target_kind == LLVMIntegerTypeKind) {
        unsigned source_width = LLVMGetIntTypeWidth(source_type);
        unsigned target_width = LLVMGetIntTypeWidth(target_type);
        
        if (target_width > source_width) {
            /* Zero extend */
            return LLVMBuildZExt(builder, value, target_type, "zext");
        } else if (target_width < source_width) {
            /* Truncate */
            return LLVMBuildTrunc(builder, value, target_type, "trunc");
        }
    }
    
    /* Float to float cast */
    if ((source_kind == LLVMFloatTypeKind || source_kind == LLVMDoubleTypeKind) && 
        (target_kind == LLVMFloatTypeKind || target_kind == LLVMDoubleTypeKind)) {
        
        if (source_kind == LLVMFloatTypeKind && target_kind == LLVMDoubleTypeKind) {
            /* Float to double */
            return LLVMBuildFPExt(builder, value, target_type, "fpext");
        } else if (source_kind == LLVMDoubleTypeKind && target_kind == LLVMFloatTypeKind) {
            /* Double to float */
            return LLVMBuildFPTrunc(builder, value, target_type, "fptrunc");
        }
    }
    
    /* Integer to float cast (unsigned) */
    if (source_kind == LLVMIntegerTypeKind && 
        (target_kind == LLVMFloatTypeKind || target_kind == LLVMDoubleTypeKind)) {
        
        return LLVMBuildUIToFP(builder, value, target_type, "uitofp");
    }
    
    /* Float to integer cast (unsigned) */
    if ((source_kind == LLVMFloatTypeKind || source_kind == LLVMDoubleTypeKind) && 
        target_kind == LLVMIntegerTypeKind) {
        
        return LLVMBuildFPToUI(builder, value, target_type, "fptoui");
    }
    
    /* Bitcast for same-sized types */
    if (LLVMSizeOf(source_type) == LLVMSizeOf(target_type)) {
        return LLVMBuildBitCast(builder, value, target_type, "bitcast");
    }
    
    report_error_simple(ERROR_ERROR, ERR_INVALID_CAST, "Invalid explicit cast");
    return NULL;
}

/* Promote types for binary operations */
LLVMTypeRef promote_types(LLVMTypeRef type1, LLVMTypeRef type2) {
    if (!type1 || !type2) {
        return NULL;
    }
    
    LLVMTypeKind kind1 = LLVMGetTypeKind(type1);
    LLVMTypeKind kind2 = LLVMGetTypeKind(type2);
    
    /* If types are the same, no promotion needed */
    if (type1 == type2) {
        return type1;
    }
    
    /* Double has highest precedence */
    if (kind1 == LLVMDoubleTypeKind || kind2 == LLVMDoubleTypeKind) {
        return LLVMDoubleType();
    }
    
    /* Float has next highest precedence */
    if (kind1 == LLVMFloatTypeKind || kind2 == LLVMFloatTypeKind) {
        return LLVMFloatType();
    }
    
    /* For integers, use the wider type */
    if (kind1 == LLVMIntegerTypeKind && kind2 == LLVMIntegerTypeKind) {
        unsigned width1 = LLVMGetIntTypeWidth(type1);
        unsigned width2 = LLVMGetIntTypeWidth(type2);
        
        if (width1 >= width2) {
            return type1;
        } else {
            return type2;
        }
    }
    
    /* Handle boolean and integer */
    if (kind1 == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(type1) == 1 && 
        kind2 == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(type2) > 1) {
        return type2;
    }
    
    if (kind2 == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(type2) == 1 && 
        kind1 == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(type1) > 1) {
        return type1;
    }
    
    /* Handle pointer and integer */
    if (kind1 == LLVMPointerTypeKind && kind2 == LLVMIntegerTypeKind) {
        return type1;
    }
    
    if (kind2 == LLVMPointerTypeKind && kind1 == LLVMIntegerTypeKind) {
        return type2;
    }
    
    /* Handle pointer and boolean */
    if (kind1 == LLVMPointerTypeKind && 
        kind2 == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(type2) == 1) {
        return type1;
    }
    
    if (kind2 == LLVMPointerTypeKind && 
        kind1 == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(type1) == 1) {
        return type2;
    }
    
    /* Incompatible types */
    return NULL;
}

/* Create a global string constant */
LLVMValueRef create_global_string(LLVMModuleRef module, LLVMBuilderRef builder, 
                                 const char *string, const char *name) {
    if (!module || !builder || !string) {
        return NULL;
    }
    
    /* Create global string constant */
    LLVMValueRef global_str = LLVMBuildGlobalStringPtr(builder, string, name);
    
    return global_str;
}

/* Create a constant integer */
LLVMValueRef create_constant_int(int value, LLVMTypeRef type) {
    if (!type || LLVMGetTypeKind(type) != LLVMIntegerTypeKind) {
        return NULL;
    }
    
    return LLVMConstInt(type, value, 1);
}

/* Create a constant float */
LLVMValueRef create_constant_float(float value, LLVMTypeRef type) {
    if (!type || (LLVMGetTypeKind(type) != LLVMFloatTypeKind && 
                 LLVMGetTypeKind(type) != LLVMDoubleTypeKind)) {
        return NULL;
    }
    
    return LLVMConstReal(type, value);
}

/* Get LLVM type from type string */
LLVMTypeRef get_llvm_type(LLVMModuleRef module, const char *type_str) {
    if (!module || !type_str) {
        return NULL;
    }
    
    /* Basic types */
    if (strcmp(type_str, "void") == 0) {
        return LLVMVoidType();
    } else if (strcmp(type_str, "bool") == 0) {
        return LLVMInt1Type();
    } else if (strcmp(type_str, "char") == 0) {
        return LLVMInt8Type();
    } else if (strcmp(type_str, "short") == 0) {
        return LLVMInt16Type();
    } else if (strcmp(type_str, "int") == 0) {
        return LLVMInt32Type();
    } else if (strcmp(type_str, "long") == 0) {
        return LLVMInt64Type();
    } else if (strcmp(type_str, "float") == 0) {
        return LLVMFloatType();
    } else if (strcmp(type_str, "double") == 0) {
        return LLVMDoubleType();
    }
    
    /* Pointer types */
    if (strstr(type_str, "*")) {
        char base_type[256];
        strncpy(base_type, type_str, strlen(type_str) - 1);
        base_type[strlen(type_str) - 1] = '\0';
        
        LLVMTypeRef pointee_type = get_llvm_type(module, base_type);
        if (!pointee_type) {
            return NULL;
        }
        
        return LLVMPointerType(pointee_type, 0);
    }
    
    /* Array types */
    if (strstr(type_str, "[") && strstr(type_str, "]")) {
        char base_type[256];
        int size;
        
        /* Parse array type string (e.g., "int[10]") */
        char *open_bracket = strchr(type_str, '[');
        if (!open_bracket) {
            return NULL;
        }
        
        /* Extract base type */
        size_t base_len = open_bracket - type_str;
        strncpy(base_type, type_str, base_len);
        base_type[base_len] = '\0';
        
        /* Extract size */
        sscanf(open_bracket + 1, "%d", &size);
        
        /* Get element type */
        LLVMTypeRef element_type = get_llvm_type(module, base_type);
        if (!element_type) {
            return NULL;
        }
        
        return LLVMArrayType(element_type, size);
    }
    
    /* Struct types */
    if (strncmp(type_str, "struct ", 7) == 0) {
        const char *struct_name = type_str + 7;
        
        /* Look up struct type in module */
        LLVMTypeRef struct_type = LLVMGetTypeByName(module, struct_name);
        if (struct_type) {
            return struct_type;
        }
        
        /* If not found, create an opaque struct type */
        struct_type = LLVMStructCreateNamed(LLVMGetGlobalContext(), struct_name);
        
        /* Note: The struct body should be set later using LLVMStructSetBody */
        return struct_type;
    }
    
    /* Function types */
    if (strstr(type_str, "(") && strstr(type_str, ")")) {
        /* Parse function type string (e.g., "int(float, char)") */
        char return_type_str[256];
        char param_types_str[256];
        
        /* Extract return type and parameter types */
        char *open_paren = strchr(type_str, '(');
        if (!open_paren) {
            return NULL;
        }
        
        /* Extract return type */
        size_t return_len = open_paren - type_str;
        strncpy(return_type_str, type_str, return_len);
        return_type_str[return_len] = '\0';
        
        /* Extract parameter types */
        char *close_paren = strchr(type_str, ')');
        if (!close_paren) {
            return NULL;
        }
        
        size_t param_len = close_paren - open_paren - 1;
        strncpy(param_types_str, open_paren + 1, param_len);
        param_types_str[param_len] = '\0';
        
        /* Get return type */
        LLVMTypeRef return_type = get_llvm_type(module, return_type_str);
        if (!return_type) {
            return NULL;
        }
        
        /* Parse parameter types */
        LLVMTypeRef param_types[16];
        unsigned param_count = 0;
        
        if (param_len > 0) {
            char *param_str = strtok(param_types_str, ",");
            while (param_str && param_count < 16) {
                /* Trim whitespace */
                while (*param_str == ' ') param_str++;
                
                LLVMTypeRef param_type = get_llvm_type(module, param_str);
                if (!param_type) {
                    return NULL;
                }
                
                param_types[param_count++] = param_type;
                param_str = strtok(NULL, ",");
            }
        }
        
        /* Create function type */
        return LLVMFunctionType(return_type, param_types, param_count, 0);
    }
    
    /* Unknown type */
    return NULL;
}

/* Add a symbol to the symbol table */
int add_symbol(SymbolTable *table, const char *name, LLVMValueRef value, 
              LLVMTypeRef type, int is_global, int is_function) {
    if (!table || !name || !value) {
        return 0;
    }
    
    /* Check if symbol already exists in current scope */
    for (size_t i = 0; i < table->entry_count; i++) {
        if (strcmp(table->entries[i].name, name) == 0) {
            return 0;
        }
    }
    
    /* Expand entries array if needed */
    if (table->entry_count >= table->capacity) {
        size_t new_capacity = table->capacity * 2;
        SymbolTableEntry *new_entries = (SymbolTableEntry *)realloc(
            table->entries, new_capacity * sizeof(SymbolTableEntry));
        
        if (!new_entries) {
            return 0;
        }
        
        table->entries = new_entries;
        table->capacity = new_capacity;
    }
    
    /* Add new entry */
    SymbolTableEntry *entry = &table->entries[table->entry_count++];
    
    entry->name = strdup(name);
    if (!entry->name) {
        table->entry_count--;
        return 0;
    }
    
    entry->value = value;
    entry->type = type;
    entry->is_global = is_global;
    entry->is_function = is_function;
    
    return 1;
}

/* Look up a symbol in the symbol table */
SymbolTableEntry *lookup_symbol(SymbolTable *table, const char *name) {
    if (!table || !name) {
        return NULL;
    }
    
    /* Search in current scope */
    for (size_t i = 0; i < table->entry_count; i++) {
        if (strcmp(table->entries[i].name, name) == 0) {
            return &table->entries[i];
        }
    }
    
    /* Search in parent scope if not found */
    if (table->parent) {
        return lookup_symbol(table->parent, name);
    }
    
    return NULL;
}

/* Create a new scope */
SymbolTable *create_scope(SymbolTable *parent) {
    SymbolTable *table = (SymbolTable *)malloc(sizeof(SymbolTable));
    if (!table) {
        return NULL;
    }
    
    table->parent = parent;
    table->capacity = 16;
    table->entry_count = 0;
    
    table->entries = (SymbolTableEntry *)malloc(table->capacity * sizeof(SymbolTableEntry));
    if (!table->entries) {
        free(table);
        return NULL;
    }
    
    return table;
}

/* Free a symbol table */
void free_symbol_table(SymbolTable *table) {
    if (!table) {
        return;
    }
    
    /* Free entry names */
    for (size_t i = 0; i < table->entry_count; i++) {
        free((void *)table->entries[i].name);
    }
    
    /* Free entries array */
    free(table->entries);
    
    /* Free table */
    free(table);
}

