#include <stdlib.h>
#include <string.h>
#include "ast.h"
#include "error.h"

/* Helper function to duplicate a string */
static char *duplicate_string(const char *str) {
    if (!str) return NULL;
    
    char *dup = strdup(str);
    if (!dup) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate memory for string");
    }
    
    return dup;
}

/* Create a program node */
ASTNode *create_program_node(ASTNode **declarations, size_t declaration_count) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_PROGRAM;
    node->data.program.declarations = declarations;
    node->data.program.declaration_count = declaration_count;
    
    return node;
}

/* Create a block node */
ASTNode *create_block_node(ASTNode **statements, size_t statement_count) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_BLOCK;
    node->data.block.statements = statements;
    node->data.block.statement_count = statement_count;
    
    return node;
}

/* Create a variable declaration node */
ASTNode *create_variable_declaration_node(const char *name, const char *type, ASTNode *initializer) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_VARIABLE_DECLARATION;
    node->data.variable_declaration.name = duplicate_string(name);
    node->data.variable_declaration.type = duplicate_string(type);
    node->data.variable_declaration.initializer = initializer;
    
    if ((name && !node->data.variable_declaration.name) || 
        (type && !node->data.variable_declaration.type)) {
        free_ast_node(node);
        return NULL;
    }
    
    return node;
}

/* Create an array declaration node */
ASTNode *create_array_declaration_node(const char *name, const char *element_type, size_t size, 
                                      ASTNode **initializers, size_t initializer_count) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_ARRAY_DECLARATION;
    node->data.array_declaration.name = duplicate_string(name);
    node->data.array_declaration.element_type = duplicate_string(element_type);
    node->data.array_declaration.size = size;
    node->data.array_declaration.initializers = initializers;
    node->data.array_declaration.initializer_count = initializer_count;
    
    if ((name && !node->data.array_declaration.name) || 
        (element_type && !node->data.array_declaration.element_type)) {
        free_ast_node(node);
        return NULL;
    }
    
    return node;
}

/* Create a struct declaration node */
ASTNode *create_struct_declaration_node(const char *name, StructField *fields, size_t field_count) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_STRUCT_DECLARATION;
    node->data.struct_declaration.name = duplicate_string(name);
    
    /* Duplicate the fields array */
    if (field_count > 0 && fields) {
        node->data.struct_declaration.fields = (StructField *)malloc(field_count * sizeof(StructField));
        if (!node->data.struct_declaration.fields) {
            free(node->data.struct_declaration.name);
            free(node);
            report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate struct fields");
            return NULL;
        }
        
        /* Copy each field */
        for (size_t i = 0; i < field_count; i++) {
            node->data.struct_declaration.fields[i].name = duplicate_string(fields[i].name);
            node->data.struct_declaration.fields[i].type = duplicate_string(fields[i].type);
            
            if ((fields[i].name && !node->data.struct_declaration.fields[i].name) || 
                (fields[i].type && !node->data.struct_declaration.fields[i].type)) {
                /* Clean up already allocated fields */
                for (size_t j = 0; j < i; j++) {
                    free(node->data.struct_declaration.fields[j].name);
                    free(node->data.struct_declaration.fields[j].type);
                }
                free(node->data.struct_declaration.fields);
                free(node->data.struct_declaration.name);
                free(node);
                report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate struct field");
                return NULL;
            }
        }
    } else {
        node->data.struct_declaration.fields = NULL;
    }
    
    node->data.struct_declaration.field_count = field_count;
    
    if (name && !node->data.struct_declaration.name) {
        free_ast_node(node);
        return NULL;
    }
    
    return node;
}

/* Create a function declaration node */
ASTNode *create_function_declaration_node(const char *name, const char *return_type, 
                                         Parameter *params, size_t param_count, ASTNode *body) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_FUNCTION_DECLARATION;
    node->data.function_declaration.name = duplicate_string(name);
    node->data.function_declaration.return_type = duplicate_string(return_type);
    
    /* Duplicate the parameters array */
    if (param_count > 0 && params) {
        node->data.function_declaration.params = (Parameter *)malloc(param_count * sizeof(Parameter));
        if (!node->data.function_declaration.params) {
            free(node->data.function_declaration.name);
            free(node->data.function_declaration.return_type);
            free(node);
            report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate function parameters");
            return NULL;
        }
        
        /* Copy each parameter */
        for (size_t i = 0; i < param_count; i++) {
            node->data.function_declaration.params[i].name = duplicate_string(params[i].name);
            node->data.function_declaration.params[i].type = duplicate_string(params[i].type);
            
            if ((params[i].name && !node->data.function_declaration.params[i].name) || 
                (params[i].type && !node->data.function_declaration.params[i].type)) {
                /* Clean up already allocated parameters */
                for (size_t j = 0; j < i; j++) {
                    free(node->data.function_declaration.params[j].name);
                    free(node->data.function_declaration.params[j].type);
                }
                free(node->data.function_declaration.params);
                free(node->data.function_declaration.name);
                free(node->data.function_declaration.return_type);
                free(node);
                report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate function parameter");
                return NULL;
            }
        }
    } else {
        node->data.function_declaration.params = NULL;
    }
    
    node->data.function_declaration.param_count = param_count;
    node->data.function_declaration.body = body;
    
    if ((name && !node->data.function_declaration.name) || 
        (return_type && !node->data.function_declaration.return_type)) {
        free_ast_node(node);
        return NULL;
    }
    
    return node;
}

/* Create a variable node */
ASTNode *create_variable_node(const char *name) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_VARIABLE;
    node->data.variable.name = duplicate_string(name);
    
    if (name && !node->data.variable.name) {
        free(node);
        return NULL;
    }
    
    return node;
}

/* Create an array access node */
ASTNode *create_array_access_node(ASTNode *array, ASTNode *index) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_ARRAY_ACCESS;
    node->data.array_access.array = array;
    node->data.array_access.index = index;
    
    return node;
}

/* Create a struct access node */
ASTNode *create_struct_access_node(ASTNode *structure, const char *field) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_STRUCT_ACCESS;
    node->data.struct_access.structure = structure;
    node->data.struct_access.field = duplicate_string(field);
    
    if (field && !node->data.struct_access.field) {
        free(node);
        return NULL;
    }
    
    return node;
}

/* Create a function call node */
ASTNode *create_function_call_node(const char *name, ASTNode **args, size_t arg_count) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_FUNCTION_CALL;
    node->data.function_call.name = duplicate_string(name);
    node->data.function_call.args = args;
    node->data.function_call.arg_count = arg_count;
    
    if (name && !node->data.function_call.name) {
        free(node);
        return NULL;
    }
    
    return node;
}

/* Create an assignment node */
ASTNode *create_assignment_node(ASTNode *lhs, ASTNode *rhs, const char *op) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_ASSIGNMENT;
    node->data.assignment.lhs = lhs;
    node->data.assignment.rhs = rhs;
    node->data.assignment.op = duplicate_string(op);
    
    if (op && !node->data.assignment.op) {
        free(node);
        return NULL;
    }
    
    return node;
}

/* Create a binary operation node */
ASTNode *create_binary_op_node(ASTNode *left, ASTNode *right, const char *op) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_BINARY_OP;
    node->data.binary_op.left = left;
    node->data.binary_op.right = right;
    node->data.binary_op.op = duplicate_string(op);
    
    if (op && !node->data.binary_op.op) {
        free(node);
        return NULL;
    }
    
    return node;
}

/* Create a unary operation node */
ASTNode *create_unary_op_node(ASTNode *operand, const char *op, int is_prefix) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_UNARY_OP;
    node->data.unary_op.operand = operand;
    node->data.unary_op.op = duplicate_string(op);
    node->data.unary_op.is_prefix = is_prefix;
    
    if (op && !node->data.unary_op.op) {
        free(node);
        return NULL;
    }
    
    return node;
}

/* Create a ternary operation node */
ASTNode *create_ternary_op_node(ASTNode *condition, ASTNode *then_expr, ASTNode *else_expr) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_TERNARY_OP;
    node->data.ternary_op.condition = condition;
    node->data.ternary_op.then_expr = then_expr;
    node->data.ternary_op.else_expr = else_expr;
    
    return node;
}

/* Create a cast node */
ASTNode *create_cast_node(ASTNode *expr, const char *type) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    node->type = NODE_CAST;
    node->data.cast.expr = expr;
    node->data.cast.type = duplicate_string(type);
    
    if (type && !node->data.cast.type) {
        free(node);
        return NULL;
    }
    
    return node;
}

/* Create an integer literal node */
ASTNode *create_integer_literal_node(int value) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_INTEGER_LITERAL;
    node->data.integer_literal = value;
    
    return node;
}

/* Create a float literal node */
ASTNode *create_float_literal_node(float value) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_FLOAT_LITERAL;
    node->data.float_literal = value;
    
    return node;
}

/* Create a string literal node */
ASTNode *create_string_literal_node(const char *value) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_STRING_LITERAL;
    node->data.string_literal = duplicate_string(value);
    
    if (value && !node->data.string_literal) {
        free(node);
        return NULL;
    }
    
    return node;
}

/* Create an if statement node */
ASTNode *create_if_statement_node(ASTNode *condition, ASTNode *then_branch, ASTNode *else_branch) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_IF_STATEMENT;
    node->data.if_statement.condition = condition;
    node->data.if_statement.then_branch = then_branch;
    node->data.if_statement.else_branch = else_branch;
    
    return node;
}

/* Create a while statement node */
ASTNode *create_while_statement_node(ASTNode *condition, ASTNode *body) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_WHILE_STATEMENT;
    node->data.while_statement.condition = condition;
    node->data.while_statement.body = body;
    
    return node;
}

/* Create a for statement node */
ASTNode *create_for_statement_node(ASTNode *init, ASTNode *condition, ASTNode *update, ASTNode *body) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_FOR_STATEMENT;
    node->data.for_statement.init = init;
    node->data.for_statement.condition = condition;
    node->data.for_statement.update = update;
    node->data.for_statement.body = body;
    
    return node;
}

/* Create a return statement node */
ASTNode *create_return_statement_node(ASTNode *expr) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_RETURN_STATEMENT;
    node->data.return_statement.expr = expr;
    
    return node;
}

/* Create a break statement node */
ASTNode *create_break_statement_node(void) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_BREAK_STATEMENT;
    
    return node;
}

/* Create a continue statement node */
ASTNode *create_continue_statement_node(void) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_CONTINUE_STATEMENT;
    
    return node;
}

/* Create an expression statement node */
ASTNode *create_expression_statement_node(ASTNode *expr) {
    ASTNode *node = (ASTNode *)malloc(sizeof(ASTNode));
    if (!node) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate AST node");
        return NULL;
    }
    
    node->type = NODE_EXPRESSION_STATEMENT;
    node->data.expression_statement.expr = expr;
    
    return node;
}

/* Free an AST node and all its children */
void free_ast_node(ASTNode *node) {
    if (!node) return;
    
    /* Free node-specific data */
    switch (node->type) {
        case NODE_PROGRAM:
            if (node->data.program.declarations) {
                for (size_t i = 0; i < node->data.program.declaration_count; i++) {
                    free_ast_node(node->data.program.declarations[i]);
                }
                free(node->data.program.declarations);
            }
            break;
            
        case NODE_BLOCK:
            if (node->data.block.statements) {
                for (size_t i = 0; i < node->data.block.statement_count; i++) {
                    free_ast_node(node->data.block.statements[i]);
                }
                free(node->data.block.statements);
            }
            break;
            
        case NODE_VARIABLE_DECLARATION:
            free(node->data.variable_declaration.name);
            free(node->data.variable_declaration.type);
            free_ast_node(node->data.variable_declaration.initializer);
            break;
            
        case NODE_ARRAY_DECLARATION:
            free(node->data.array_declaration.name);
            free(node->data.array_declaration.element_type);
            if (node->data.array_declaration.initializers) {
                for (size_t i = 0; i < node->data.array_declaration.initializer_count; i++) {
                    free_ast_node(node->data.array_declaration.initializers[i]);
                }
                free(node->data.array_declaration.initializers);
            }
            break;
            
        case NODE_STRUCT_DECLARATION:
            free(node->data.struct_declaration.name);
            if (node->data.struct_declaration.fields) {
                for (size_t i = 0; i < node->data.struct_declaration.field_count; i++) {
                    free(node->data.struct_declaration.fields[i].name);
                    free(node->data.struct_declaration.fields[i].type);
                }
                free(node->data.struct_declaration.fields);
            }
            break;
            
        case NODE_FUNCTION_DECLARATION:
            free(node->data.function_declaration.name);
            free(node->data.function_declaration.return_type);
            if (node->data.function_declaration.params) {
                for (size_t i = 0; i < node->data.function_declaration.param_count; i++) {
                    free(node->data.function_declaration.params[i].name);
                    free(node->data.function_declaration.params[i].type);
                }
                free(node->data.function_declaration.params);
            }
            free_ast_node(node->data.function_declaration.body);
            break;
            
        case NODE_VARIABLE:
            free(node->data.variable.name);
            break;
            
        case NODE_ARRAY_ACCESS:
            free_ast_node(node->data.array_access.array);
            free_ast_node(node->data.array_access.index);
            break;
            
        case NODE_STRUCT_ACCESS:
            free_ast_node(node->data.struct_access.structure);
            free(node->data.struct_access.field);
            break;
            
        case NODE_FUNCTION_CALL:
            free(node->data.function_call.name);
            if (node->data.function_call.args) {
                for (size_t i = 0; i < node->data.function_call.arg_count; i++) {
                    free_ast_node(node->data.function_call.args[i]);
                }
                free(node->data.function_call.args);
            }
            break;
            
        case NODE_ASSIGNMENT:
            free_ast_node(node->data.assignment.lhs);
            free_ast_node(node->data.assignment.rhs);
            free(node->data.assignment.op);
            break;
            
        case NODE_BINARY_OP:
            free_ast_node(node->data.binary_op.left);
            free_ast_node(node->data.binary_op.right);
            free(node->data.binary_op.op);
            break;
            
        case NODE_UNARY_OP:
            free_ast_node(node->data.unary_op.operand);
            free(node->data.unary_op.op);
            break;
            
        case NODE_TERNARY_OP:
            free_ast_node(node->data.ternary_op.condition);
            free_ast_node(node->data.ternary_op.then_expr);
            free_ast_node(node->data.ternary_op.else_expr);
            break;
            
        case NODE_CAST:
            free_ast_node(node->data.cast.expr);
            free(node->data.cast.type);
            break;
            
        case NODE_STRING_LITERAL:
            free(node->data.string_literal);
            break;
            
        case NODE_IF_STATEMENT:
            free_ast_node(node->data.if_statement.condition);
            free_ast_node(node->data.if_statement.then_branch);
            free_ast_node(node->data.if_statement.else_branch);
            break;
            
        case NODE_WHILE_STATEMENT:
            free_ast_node(node->data.while_statement.condition);
            free_ast_node(node->data.while_statement.body);
            break;
            
        case NODE_FOR_STATEMENT:
            free_ast_node(node->data.for_statement.init);
            free_ast_node(node->data.for_statement.condition);
            free_ast_node(node->data.for_statement.update);
            free_ast_node(node->data.for_statement.body);
            break;
            
        case NODE_RETURN_STATEMENT:
            free_ast_node(node->data.return_statement.expr);
            break;
            
        case NODE_EXPRESSION_STATEMENT:
            free_ast_node(node->data.expression_statement.expr);
            break;
            
        case NODE_INTEGER_LITERAL:
        case NODE_FLOAT_LITERAL:
        case NODE_BREAK_STATEMENT:
        case NODE_CONTINUE_STATEMENT:
            /* These nodes don't have any dynamically allocated data */
            break;
    }
    
    /* Free the node itself */
    free(node);
}

