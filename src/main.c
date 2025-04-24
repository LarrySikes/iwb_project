#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "compiler.h"
#include "error.h"

/* Print usage information */
static void print_usage(const char *program_name) {
    printf("Usage: %s [options] input_file\n", program_name);
    printf("Options:\n");
    printf("  -o, --output <file>       Output file (default: input_file.bc)\n");
    printf("  -O<level>                 Optimization level (0-3, default: 0)\n");
    printf("  -t, --target <triple>     Target triple (default: host target)\n");
    printf("  -g                        Emit debug information\n");
    printf("  -v, --verbose             Verbose output\n");
    printf("  --dump-ast                Dump AST to stdout\n");
    printf("  --dump-llvm               Dump LLVM IR to stdout\n");
    printf("  --verify                  Verify LLVM module\n");
    printf("  -h, --help                Display this help message\n");
}

int main(int argc, char *argv[]) {
    /* Default compiler options */
    CompilerOptions options;
    init_compiler_options(&options);
    
    /* Parse command line options */
    int opt;
    int option_index = 0;
    
    static struct option long_options[] = {
        {"output", required_argument, 0, 'o'},
        {"target", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"dump-ast", no_argument, 0, 'a'},
        {"dump-llvm", no_argument, 0, 'l'},
        {"verify", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "o:O:t:gvh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'o':
                options.output_file = optarg;
                break;
            case 'O':
                options.optimization_level = atoi(optarg);
                if (options.optimization_level < 0 || options.optimization_level > 3) {
                    fprintf(stderr, "Invalid optimization level: %s\n", optarg);
                    return 1;
                }
                break;
            case 't':
                options.target_triple = optarg;
                break;
            case 'g':
                options.emit_debug_info = 1;
                break;
            case 'v':
                options.verbose = 1;
                break;
            case 'a':
                options.dump_ast = 1;
                break;
            case 'l':
                options.dump_llvm_ir = 1;
                break;
            case 'V':
                options.verify_module = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    /* Check for input file */
    if (optind >= argc) {
        fprintf(stderr, "Error: No input file specified\n");
        print_usage(argv[0]);
        return 1;
    }
    
    options.input_file = argv[optind];
    
    /* If no output file specified, use input file with .bc extension */
    if (!options.output_file) {
        char *output_file = malloc(strlen(options.input_file) + 4);
        if (!output_file) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            return 1;
        }
        
        strcpy(output_file, options.input_file);
        
        /* Replace extension with .bc or add .bc if no extension */
        char *dot = strrchr(output_file, '.');
        if (dot) {
            strcpy(dot, ".bc");
        } else {
            strcat(output_file, ".bc");
        }
        
        options.output_file = output_file;
    }
    
    /* Initialize compiler */
    init_compiler();
    
    /* Compile the file */
    int result = compile_file(options.input_file, options.output_file, &options);
    
    /* Clean up */
    cleanup_compiler();
    
    /* Free allocated memory */
    if (options.output_file != argv[optind] && options.output_file != optarg) {
        free((void *)options.output_file);
    }
    
    return result ? 0 : 1;
}


