
set(CMAKE_AUTOMOC ON)

add_library(hufcrypt_core STATIC
    hufcrypt_core.cpp
    hufcrypt_core.h
)

target_include_directories(hufcrypt_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})


target_link_libraries(hufcrypt_core PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Qt6::Core
)

target_compile_features(hufcrypt_core PRIVATE cxx_std_17)

