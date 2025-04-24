#ifndef AST_H
#define AST_H

#include <stddef.h>

/* AST node types */
typedef enum {
    NODE_PROGRAM,
    NODE_BLOCK,
    NODE_VARIABLE_DECLARATION,
    NODE_ARRAY_DECLARATION,
    NODE_STRUCT_DECLARATION,
    NODE_FUNCTION_DECLARATION,
    NODE_VARIABLE,
    NODE_ARRAY_ACCESS,
    NODE_STRUCT_ACCESS,
    NODE_FUNCTION_CALL,
    NODE_ASSIGNMENT,
    NODE_BINARY_OP,
    NODE_UNARY_OP,
    NODE_TERNARY_OP,
    NODE_CAST,
    NODE_INTEGER_LITERAL,
    NODE_FLOAT_LITERAL,
    NODE_STRING_LITERAL,
    NODE_IF_STATEMENT,
    NODE_WHILE_STATEMENT,
    NODE_FOR_STATEMENT,
    NODE_RETURN_STATEMENT,
    NODE_BREAK_STATEMENT,
    NODE_CONTINUE_STATEMENT,
    NODE_EXPRESSION_STATEMENT
} ASTNodeType;

/* Forward declaration of ASTNode */
typedef struct ASTNode ASTNode;

/* Struct field */
typedef struct {
    char *name;
    char *type;
} StructField;

/* Function parameter */
typedef struct {
    char *name;
    char *type;
} Parameter;

/* AST node structure */
struct ASTNode {
    ASTNodeType type;
    
    union {
        /* Program */
        struct {
            ASTNode **declarations;
            size_t declaration_count;
        } program;
        
        /* Block */
        struct {
            ASTNode **statements;
            size_t statement_count;
        } block;
        
        /* Variable declaration */
        struct {
            char *name;
            char *type;
            ASTNode *initializer;  /* Can be NULL */
        } variable_declaration;
        
        /* Array declaration */
        struct {
            char *name;
            char *element_type;
            size_t size;
            ASTNode **initializers;  /* Can be NULL */
            size_t initializer_count;
        } array_declaration;
        
        /* Struct declaration */
        struct {
            char *name;
            StructField *fields;
            size_t field_count;
        } struct_declaration;
        
        /* Function declaration */
        struct {
            char *name;
            char *return_type;
            Parameter *params;
            size_t param_count;
            ASTNode *body;  /* Block node */
        } function_declaration;
        
        /* Variable */
        struct {
            char *name;
        } variable;
        
        /* Array access */
        struct {
            ASTNode *array;
            ASTNode *index;
        } array_access;
        
        /* Struct access */
        struct {
            ASTNode *structure;
            char *field;
        } struct_access;
        
        /* Function call */
        struct {
            char *name;
            ASTNode **args;
            size_t arg_count;
        } function_call;
        
        /* Assignment */
        struct {
            ASTNode *lhs;
            ASTNode *rhs;
            char *op;  /* "=", "+=", "-=", etc. */
        } assignment;
        
        /* Binary operation */
        struct {
            ASTNode *left;
            ASTNode *right;
            char *op;  /* "+", "-", "*", etc. */
        } binary_op;
        
        /* Unary operation */
        struct {
            ASTNode *operand;
            char *op;  /* "-", "!", "~", etc. */
            int is_prefix;  /* 1 for prefix, 0 for postfix */
        } unary_op;
        
        /* Ternary operation */
        struct {
            ASTNode *condition;
            ASTNode *then_expr;
            ASTNode *else_expr;
        } ternary_op;
        
        /* Type cast */
        struct {
            ASTNode *expr;
            char *type;
        } cast;
        
        /* Literals */
        int integer_literal;
        double float_literal;
        char *string_literal;
        
        /* If statement */
        struct {
            ASTNode *condition;
            ASTNode *then_branch;
            ASTNode *else_branch;  /* Can be NULL */
        } if_statement;
        
        /* While statement */
        struct {
            ASTNode *condition;
            ASTNode *body;
        } while_statement;
        
        /* For statement */
        struct {
            ASTNode *init;  /* Can be NULL */
            ASTNode *condition;  /* Can be NULL */
            ASTNode *update;  /* Can be NULL */
            ASTNode *body;
        } for_statement;
        
        /* Return statement */
        struct {
            ASTNode *expr;  /* Can be NULL for void return */
        } return_statement;
        
        /* Expression statement */
        struct {
            ASTNode *expr;
        } expression_statement;
    } data;
};

/* AST node creation functions */
ASTNode *create_program_node(ASTNode **declarations, size_t declaration_count);
ASTNode *create_block_node(ASTNode **statements, size_t statement_count);
ASTNode *create_variable_declaration_node(const char *name, const char *type, ASTNode *initializer);
ASTNode *create_array_declaration_node(const char *name, const char *element_type, size_t size, 
                                      ASTNode **initializers, size_t initializer_count);
ASTNode *create_struct_declaration_node(const char *name, StructField *fields, size_t field_count);
ASTNode *create_function_declaration_node(const char *name, const char *return_type, 
                                         Parameter *params, size_t param_count, ASTNode *body);
ASTNode *create_variable_node(const char *name);
ASTNode *create_array_access_node(ASTNode *array, ASTNode *index);
ASTNode *create_struct_access_node(ASTNode *structure, const char *field);
ASTNode *create_function_call_node(const char *name, ASTNode **args, size_t arg_count);
ASTNode *create_assignment_node(ASTNode *lhs, ASTNode *rhs, const char *op);
ASTNode *create_binary_op_node(ASTNode *left, ASTNode *right, const char *op);
ASTNode *create_unary_op_node(ASTNode *operand, const char *op, int is_prefix);
ASTNode *create_ternary_op_node(ASTNode *condition, ASTNode *then_expr, ASTNode *else_expr);
ASTNode *create_cast_node(ASTNode *expr, const char *type);
ASTNode *create_integer_literal_node(int value);
ASTNode *create_float_literal_node(double value);
ASTNode *create_string_literal_node(const char *value);
ASTNode *create_if_statement_node(ASTNode *condition, ASTNode *then_branch, ASTNode *else_branch);
ASTNode *create_while_statement_node(ASTNode *condition, ASTNode *body);
ASTNode *create_for_statement_node(ASTNode *init, ASTNode *condition, ASTNode *update, ASTNode *body);
ASTNode *create_return_statement_node(ASTNode *expr);
ASTNode *create_break_statement_node(void);
ASTNode *create_continue_statement_node(void);
ASTNode *create_expression_statement_node(ASTNode *expr);

/* AST node destruction */
void free_ast_node(ASTNode *node);

#endif /* AST_H */

