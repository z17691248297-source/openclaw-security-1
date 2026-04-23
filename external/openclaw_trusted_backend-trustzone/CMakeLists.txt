project (optee_example_openclaw_trusted_backend C)

set (CA_TARGET ${PROJECT_NAME})
set (SERVER_TARGET optee_example_openclaw_trusted_backend_server)

add_executable (${CA_TARGET} host/main.c)
add_executable (${SERVER_TARGET} host/backend_server_c.c)

target_include_directories(${CA_TARGET}
			   PRIVATE ta/include
			   PRIVATE include)

target_include_directories(${SERVER_TARGET}
			   PRIVATE ta/include
			   PRIVATE include)

target_link_libraries (${CA_TARGET} PRIVATE teec crypto)
target_link_libraries (${SERVER_TARGET} PRIVATE crypto)

install (TARGETS ${CA_TARGET} ${SERVER_TARGET}
	 DESTINATION ${CMAKE_INSTALL_BINDIR})
