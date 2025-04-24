#ifndef SYMBOL_TABLE_H
#define SYMBOL_TABLE_H

#include <llvm-c/Core.h>

/* Symbol table entry */
typedef struct SymbolTableEntry {
    char *name;
    LLVMValueRef value;       /* LLVM value (variable, function, etc.) */
    LLVMTypeRef type;         /* LLVM type (for struct types) */
    int is_function;          /* Flag for function symbols */
    int is_global;            /* Flag for global symbols */
    struct SymbolTableEntry *next;  /* Next entry in the same bucket */
} SymbolTableEntry;

/* Symbol table */
typedef struct SymbolTable {
    SymbolTableEntry **buckets;
    size_t bucket_count;
    struct SymbolTable *parent;  /* Parent scope, NULL for global scope */
} SymbolTable;

/* Symbol table functions */
SymbolTable *create_symbol_table(size_t bucket_count, SymbolTable *parent);
void free_symbol_table(SymbolTable *table);
unsigned int hash_string(const char *str, size_t bucket_count);
int add_symbol(SymbolTable *table, const char *name, LLVMValueRef value, LLVMTypeRef type, int is_function, int is_global);
SymbolTableEntry *lookup_symbol(SymbolTable *table, const char *name);
SymbolTableEntry *lookup_symbol_current_scope(SymbolTable *table, const char *name);
SymbolTable *create_scope(SymbolTable *parent);
void exit_scope(SymbolTable *table);

#endif /* SYMBOL_TABLE_H */

