cmake_minimum_required(VERSION 3.16)

project(Lab_1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

# ВАЖНО! Укажите тут путь к директории OpenSSL на Вашем компьютере
set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
find_package(OpenSSL REQUIRED)

set(SOURCES
    main.cpp
    CryptoManager.cpp
    FileUtils.cpp
)

set(HEADERS
    CryptoManager.h
    FileUtils.h
    FileInfo.h
)

add_executable(Lab_1
    ${SOURCES}
    ${HEADERS}
)

target_link_libraries(Lab_1
    Qt${QT_VERSION_MAJOR}::Core
    OpenSSL::SSL
    OpenSSL::Crypto
)

include(GNUInstallDirs)
install(TARGETS Lab_1
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
