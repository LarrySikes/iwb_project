#include <stdlib.h>
#include <string.h>
#include "symbol_table.h"
#include "error.h"

/* Create a new symbol table */
SymbolTable *create_symbol_table(size_t bucket_count, SymbolTable *parent) {
    SymbolTable *table = (SymbolTable *)malloc(sizeof(SymbolTable));
    if (!table) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate symbol table");
        return NULL;
    }
    
    table->buckets = (SymbolTableEntry **)calloc(bucket_count, sizeof(SymbolTableEntry *));
    if (!table->buckets) {
        free(table);
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate symbol table buckets");
        return NULL;
    }
    
    table->bucket_count = bucket_count;
    table->parent = parent;
    
    return table;
}

/* Free a symbol table and all its entries */
void free_symbol_table(SymbolTable *table) {
    if (!table) return;
    
    /* Free all entries in each bucket */
    for (size_t i = 0; i < table->bucket_count; i++) {
        SymbolTableEntry *entry = table->buckets[i];
        while (entry) {
            SymbolTableEntry *next = entry->next;
            free(entry->name);
            free(entry);
            entry = next;
        }
    }
    
    /* Free the buckets array and the table itself */
    free(table->buckets);
    free(table);
}

/* Hash function for symbol names */
unsigned int hash_string(const char *str, size_t bucket_count) {
    if (!str) return 0;
    
    unsigned int hash = 0;
    while (*str) {
        hash = hash * 31 + (*str++);
    }
    
    return hash % bucket_count;
}

/* Add a symbol to the table */
int add_symbol(SymbolTable *table, const char *name, LLVMValueRef value, LLVMTypeRef type, 
              int is_function, int is_global) {
    if (!table || !name) {
        report_error_simple(ERROR_ERROR, ERR_INVALID_OPERATION, "Invalid symbol table operation");
        return 0;
    }
    
    /* Check if symbol already exists in current scope */
    if (lookup_symbol_current_scope(table, name)) {
        report_error_format(ERROR_ERROR, ERR_DUPLICATE_SYMBOL, NULL, 
                           "Symbol '%s' already defined in current scope", name);
        return 0;
    }
    
    /* Create new entry */
    SymbolTableEntry *entry = (SymbolTableEntry *)malloc(sizeof(SymbolTableEntry));
    if (!entry) {
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate symbol table entry");
        return 0;
    }
    
    /* Copy the name */
    entry->name = strdup(name);
    if (!entry->name) {
        free(entry);
        report_error_simple(ERROR_ERROR, ERR_MEMORY_ALLOCATION, "Failed to allocate symbol name");
        return 0;
    }
    
    /* Initialize other fields */
    entry->value = value;
    entry->type = type;
    entry->is_function = is_function;
    entry->is_global = is_global;
    
    /* Add to the appropriate bucket */
    unsigned int bucket = hash_string(name, table->bucket_count);
    entry->next = table->buckets[bucket];
    table->buckets[bucket] = entry;
    
    return 1;
}

/* Look up a symbol in the current scope and parent scopes */
SymbolTableEntry *lookup_symbol(SymbolTable *table, const char *name) {
    if (!table || !name) return NULL;
    
    /* Try to find in current scope */
    unsigned int bucket = hash_string(name, table->bucket_count);
    SymbolTableEntry *entry = table->buckets[bucket];
    
    while (entry) {
        if (strcmp(entry->name, name) == 0) {
            return entry;
        }
        entry = entry->next;
    }
    
    /* If not found and we have a parent scope, try there */
    if (table->parent) {
        return lookup_symbol(table->parent, name);
    }
    
    /* Not found */
    return NULL;
}

/* Look up a symbol in the current scope only */
SymbolTableEntry *lookup_symbol_current_scope(SymbolTable *table, const char *name) {
    if (!table || !name) return NULL;
    
    unsigned int bucket = hash_string(name, table->bucket_count);
    SymbolTableEntry *entry = table->buckets[bucket];
    
    while (entry) {
        if (strcmp(entry->name, name) == 0) {
            return entry;
        }
        entry = entry->next;
    }
    
    /* Not found in current scope */
    return NULL;
}

/* Create a new scope (child of the current scope) */
SymbolTable *create_scope(SymbolTable *parent) {
    return create_symbol_table(parent ? parent->bucket_count : 256, parent);
}

/* Exit the current scope (return to parent scope) */
void exit_scope(SymbolTable *table) {
    if (!table) return;
    
    SymbolTable *parent = table->parent;
    free_symbol_table(table);
    
    /* Note: The caller is responsible for updating their pointer to the parent scope */
}

