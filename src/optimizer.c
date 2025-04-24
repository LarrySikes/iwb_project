/**
 * optimizer.c - Code optimization
 * 
 * This file contains functions for optimizing LLVM IR code.
 */

#include "optimizer.h"
#include <llvm-c/Core.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/Transforms/Scalar.h>
#include <llvm-c/Transforms/IPO.h>
#include <llvm-c/Transforms/Vectorize.h>
#include <llvm-c/Transforms/Utils.h>
#include <stdio.h>

/**
 * Optimize the given LLVM module
 */
int optimize_module(LLVMModuleRef module, int level) {
    if (!module || level < 0 || level > 3) {
        return 0;
    }
    
    /* Skip optimization if level is 0 */
    if (level == 0) {
        return 1;
    }
    
    /* Create pass manager */
    LLVMPassManagerRef pass_manager = LLVMCreatePassManager();
    if (!pass_manager) {
        fprintf(stderr, "Error: Failed to create pass manager\n");
        return 0;
    }
    
    /* Add analysis passes */
    LLVMAddVerifierPass(pass_manager);
    
    /* Run function-level optimizations */
    optimize_functions(module, level);
    
    /* Run module-level optimizations */
    optimize_module_level(module, level);
    
    /* Run the pass manager */
    LLVMRunPassManager(pass_manager, module);
    
    /* Clean up */
    LLVMDisposePassManager(pass_manager);
    
    return 1;
}

/**
 * Run function-level optimizations
 */
void optimize_functions(LLVMModuleRef module, int level) {
    /* Create function pass manager */
    LLVMPassManagerRef func_pass_manager = LLVMCreateFunctionPassManagerForModule(module);
    
    /* Add analysis passes */
    LLVMAddVerifierPass(func_pass_manager);
    
    /* Add optimization passes based on level */
    /* Basic optimizations (level >= 1) */
    LLVMAddBasicAliasAnalysisPass(func_pass_manager);
    LLVMAddInstructionCombiningPass(func_pass_manager);
    LLVMAddReassociatePass(func_pass_manager);
    LLVMAddGVNPass(func_pass_manager);
    LLVMAddCFGSimplificationPass(func_pass_manager);
    
    /* Intermediate optimizations (level >= 2) */
    if (level >= 2) {
        LLVMAddTailCallEliminationPass(func_pass_manager);
        LLVMAddJumpThreadingPass(func_pass_manager);
        LLVMAddCorrelatedValuePropagationPass(func_pass_manager);
        LLVMAddEarlyCSEPass(func_pass_manager);
        LLVMAddLowerExpectIntrinsicPass(func_pass_manager);
    }
    
    /* Advanced optimizations (level >= 3) */
    if (level >= 3) {
        LLVMAddAggressiveDCEPass(func_pass_manager);
        LLVMAddInstructionCombiningPass(func_pass_manager);
        LLVMAddJumpThreadingPass(func_pass_manager);
        LLVMAddLoopVectorizePass(func_pass_manager);
        LLVMAddSLPVectorizePass(func_pass_manager);
    }
    
    /* Initialize and run the function pass manager */
    LLVMInitializeFunctionPassManager(func_pass_manager);
    
    /* Run the optimizations on each function */
    LLVMValueRef function = LLVMGetFirstFunction(module);
    while (function) {
        LLVMRunFunctionPassManager(func_pass_manager, function);
        function = LLVMGetNextFunction(function);
    }
    
    /* Finalize the function pass manager */
    LLVMFinalizeFunctionPassManager(func_pass_manager);
    
    /* Clean up */
    LLVMDisposePassManager(func_pass_manager);
}

/**
 * Run module-level optimizations
 */
void optimize_module_level(LLVMModuleRef module, int level) {
    /* Create module pass manager */
    LLVMPassManagerRef module_pass_manager = LLVMCreatePassManager();
    
    /* Add optimization passes based on level */
    /* Basic optimizations (level >= 1) */
    LLVMAddGlobalDCEPass(module_pass_manager);
    LLVMAddGlobalOptimizerPass(module_pass_manager);
    LLVMAddIPConstantPropagationPass(module_pass_manager);
    LLVMAddDeadArgEliminationPass(module_pass_manager);
    
    /* Intermediate optimizations (level >= 2) */
    if (level >= 2) {
        LLVMAddPruneEHPass(module_pass_manager);
        LLVMAddFunctionInliningPass(module_pass_manager);
        LLVMAddFunctionAttrsPass(module_pass_manager);
    }
    
    /* Advanced optimizations (level >= 3) */
    if (level >= 3) {
        LLVMAddGlobalDCEPass(module_pass_manager);
        LLVMAddConstantMergePass(module_pass_manager);
        LLVMAddArgumentPromotionPass(module_pass_manager);
        LLVMAddIPSCCPPass(module_pass_manager);
    }
    
    /* Run the module pass manager */
    LLVMRunPassManager(module_pass_manager, module);
    
    /* Clean up */
    LLVMDisposePassManager(module_pass_manager);
}

