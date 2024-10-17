set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

macro (add_test _name)
	add_executable(${_name} "test_${_name}.cpp")
    target_link_libraries(${_name} OCEAN-Protocols) 
endmacro()

# Tests
add_test(relu)
add_test(conv)
add_test(reluconv)
add_test(oceanpub)