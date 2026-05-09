find_package(OpenSSL REQUIRED)

set(source_files
    model/bs-relay-app.cc
    model/vanet-message.cc
    model/ecc-crypto.cc
    model/vanet-stats.cc
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
    model/vanet-stats.h
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
