include(ExternalProject)

ExternalProject_Add(libsodium
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libsodium
  CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/configure --prefix=${CMAKE_CURRENT_BINARY_DIR}
  BUILD_COMMAND ${MAKE}
)

add_library(sodium STATIC IMPORTED GLOBAL)
add_dependencies(sodium libsodium)
set_target_properties(sodium PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/lib/libsodium${CMAKE_STATIC_LIBRARY_SUFFIX})

set(SODIUM_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include PARENT_SCOPE)
