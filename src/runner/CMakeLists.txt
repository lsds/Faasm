set(RUNNER_LIBS
        faaslet_lib
        wavmmodule
        wamrmodule
        system
        )

add_executable(func_runner func_runner.cpp)
target_link_libraries(func_runner ${RUNNER_LIBS})

add_executable(func_sym func_sym.cpp)
target_link_libraries(func_sym ${RUNNER_LIBS})

# Main entrypoint for worker nodes
add_executable(pool_runner pool_runner.cpp)
target_link_libraries(pool_runner ${RUNNER_LIBS})

set(CODEGEN_LIBS
        wavmmodule
        wamrmodule
        system
)

add_executable(codegen_shared_obj codegen_shared_obj.cpp)
target_link_libraries(codegen_shared_obj ${CODEGEN_LIBS})

add_executable(codegen_func codegen_func.cpp)
target_link_libraries(codegen_func ${CODEGEN_LIBS})
