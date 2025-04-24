# Test CMakeLists.txt

# Add test executable
add_executable(test_iwb2llvm
    test_main.c
    test_ast.c
    test_symbol_table.c
    test_codegen.c
)

# Link against project code and testing framework
target_link_libraries(test_iwb2llvm
    ${llvm_libs}
)

# Add test cases
add_test(NAME test_ast COMMAND test_iwb2llvm ast)
add_test(NAME test_symbol_table COMMAND test_iwb2llvm symbol_table)
add_test(NAME test_codegen COMMAND test_iwb2llvm codegen)

# Add integration tests
file(GLOB TEST_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/cases/*.iwb")
foreach(TEST_SOURCE ${TEST_SOURCES})
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
    add_test(
        NAME integration_${TEST_NAME}
        COMMAND ${CMAKE_BINARY_DIR}/iwb2llvm ${TEST_SOURCE} -o ${TEST_NAME}.bc
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endforeach()

# Create test directory
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/cases)

# Copy test cases to build directory
file(GLOB TEST_FILES "${CMAKE_CURRENT_SOURCE_DIR}/cases/*")
foreach(TEST_FILE ${TEST_FILES})
    get_filename_component(FILENAME ${TEST_FILE} NAME)
    configure_file(${TEST_FILE} ${CMAKE_CURRENT_BINARY_DIR}/cases/${FILENAME} COPYONLY)
endforeach()

