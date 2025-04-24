/**
 * optimizer.h - Code optimization
 * 
 * This file contains functions for optimizing LLVM IR code.
 */

#ifndef OPTIMIZER_H
#define OPTIMIZER_H

#include <llvm-c/Core.h>

/**
 * Optimize the given LLVM module
 * 
 * @param module The LLVM module to optimize
 * @param level Optimization level (0-3)
 * @return 1 on success, 0 on failure
 */
int optimize_module(LLVMModuleRef module, int level);

/**
 * Run function-level optimizations
 * 
 * @param module The LLVM module
 * @param level Optimization level (0-3)
 */
void optimize_functions(LLVMModuleRef module, int level);

/**
 * Run module-level optimizations
 * 
 * @param module The LLVM module
 * @param level Optimization level (0-3)
 */
void optimize_module_level(LLVMModuleRef module, int level);

#endif /* OPTIMIZER_H */

