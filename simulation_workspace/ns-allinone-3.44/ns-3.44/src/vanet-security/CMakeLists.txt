find_package(OpenSSL REQUIRED)

option(VANET_SECURITY_ENABLE_PBC "Enable PBC (Pairing-Based Cryptography) support" OFF)

if(VANET_SECURITY_ENABLE_PBC)
  find_path(PBC_INCLUDE_DIR NAMES pbc/pbc.h pbc.h)
  find_library(PBC_LIBRARY pbc)
  if(NOT PBC_INCLUDE_DIR OR NOT PBC_LIBRARY)
    message(FATAL_ERROR "PBC requested but not found. Install libpbc-dev or set PBC_INCLUDE_DIR/PBC_LIBRARY.")
  endif()
  # Export the compile definition via the module interface for scratches/modules.
  add_compile_definitions(VANET_SECURITY_USE_PBC=1)
endif()

set(source_files
    model/bs-relay-app.cc
    model/vanet-message.cc
    model/ecc-crypto.cc
    model/pbc-crypto.cc
    model/fl-vanet-apps.cc
    model/vanet-stats.cc
    model/vanet-power-model.cc
    model/ta-app.cc
    model/kgc-app.cc
    model/bs-app.cc
    model/rsu-app.cc
    model/vehicle-app.cc
)

set(header_files
    model/bs-relay-app.h
    model/vanet-message.h
    model/ecc-crypto.h
    model/pbc-crypto.h
    model/fl-vanet-apps.h
    model/vanet-stats.h
    model/vanet-power-model.h
    model/ta-app.h
    model/kgc-app.h
    model/bs-app.h
    model/rsu-app.h
    model/vehicle-app.h
    model/vanet-security.h
)

set(libraries_to_link
    ${libcore}
    ${libnetwork}
    ${libinternet}
    ${libapplications}
)

if(VANET_SECURITY_ENABLE_PBC)
  list(APPEND libraries_to_link ${PBC_LIBRARY})
endif()

build_lib(
  LIBNAME vanet-security
  SOURCE_FILES ${source_files}
  HEADER_FILES ${header_files}
  LIBRARIES_TO_LINK ${libraries_to_link} OpenSSL::Crypto
)

target_include_directories(
  ${libvanet-security}
  PRIVATE ${OPENSSL_INCLUDE_DIR}
)

if(VANET_SECURITY_ENABLE_PBC)
  target_include_directories(
    ${libvanet-security}
    PUBLIC ${PBC_INCLUDE_DIR}
  )
  target_compile_definitions(
    ${libvanet-security}
    PUBLIC VANET_SECURITY_USE_PBC=1
  )
endif()
