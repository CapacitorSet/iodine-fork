add_library(iodine_transport_server server.cpp)
add_custom_target(
    iodined
    COMMAND make
    WORKING_DIRECTORY /c/bizarre-net/src/transports/iodine/iodine-src
)
target_link_libraries(iodine_transport_server /c/bizarre-net/src/transports/iodine/iodine-src/iodined.o bizarre_common z)
add_dependencies(iodine_transport_server iodined)