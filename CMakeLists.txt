cmake_minimum_required(VERSION 3.10)
project(iwb2llvm C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find LLVM
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# Include LLVM directories
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# Include our own include directory
include_directories(${CMAKE_SOURCE_DIR}/../include)

# Source files
set(SOURCES
    ${CMAKE_SOURCE_DIR}/../src/main.c
    ${CMAKE_SOURCE_DIR}/../src/ast.c
    ${CMAKE_SOURCE_DIR}/../src/symbol_table.c
    ${CMAKE_SOURCE_DIR}/../src/codegen_utils.c
    ${CMAKE_SOURCE_DIR}/../src/codegen_expr.c
    ${CMAKE_SOURCE_DIR}/../src/codegen_stmt.c
    ${CMAKE_SOURCE_DIR}/../src/codegen_decl.c
    ${CMAKE_SOURCE_DIR}/../src/error.c
    ${CMAKE_SOURCE_DIR}/../src/compiler.c
)

# Create executable
add_executable(iwb2llvm ${SOURCES})

# Link against LLVM libraries
llvm_map_components_to_libnames(llvm_libs support core irreader bitwriter analysis)
target_link_libraries(iwb2llvm ${llvm_libs})

# Enable warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(iwb2llvm PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Add tests
enable_testing()
add_subdirectory(${CMAKE_SOURCE_DIR}/../test)

# Install
install(TARGETS iwb2llvm DESTINATION bin)

