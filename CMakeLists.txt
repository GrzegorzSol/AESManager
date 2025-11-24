cmake_minimum_required(VERSION 4.0)
project(AESManager)

set(CMAKE_CXX_STANDARD 17) # Standart C++
set(CMAKE_EXE_LINKER_FLAGS "-static") # !!!
# Prywatne zmienne
set(MAIN_SOURCE main.cpp) # Główny plik źródłowy
set(MAIN_RESOURCE AESManager.rc)
set(MAIN_RESOURCE_H AESManager_resource.h)
set(PROJECT_NAME "AESManager")

# Tu będą operacje na numerze wersji
file(READ "${CMAKE_SOURCE_DIR}/version.txt" VERSION_TEXT)
string(STRIP "${VERSION_TEXT}" VERSION_TEXT)
string(REPLACE "." ";" VERSION_PARTS "${VERSION_TEXT}")
list(GET VERSION_PARTS 0 MAJOR)
list(GET VERSION_PARTS 1 MINOR)
list(GET VERSION_PARTS 2 PATCH)
list(GET VERSION_PARTS 3 BUILD)
math(EXPR BUILD "${BUILD} + 1")
set(NEW_VERSION "${MAJOR}.${MINOR}.${PATCH}.${BUILD}")
file(WRITE "${CMAKE_SOURCE_DIR}/version.txt" "${NEW_VERSION}")
message("NEW_VERSION: " ${NEW_VERSION})

# 2) Odczyt nowego numeru wersji
file(READ "${CMAKE_SOURCE_DIR}/version.txt" PROJECT_VERSION_STR)
string(STRIP "${PROJECT_VERSION_STR}" PROJECT_VERSION_STR)
# przygotuj formę z przecinkami (dla VERSIONINFO wymaga przecinków)
string(REPLACE "." "," PROJECT_VERSION_COMMA "${PROJECT_VERSION_STR}")
set(PROJECT_VERSION "${PROJECT_VERSION_COMMA}")
set(PROJECT_VERSION_STR "${PROJECT_VERSION_STR}")
# message("Z przecinkiem: " ${PROJECT_VERSION_COMMA})

# 3) generuj version.rc z szablonu
configure_file(${CMAKE_SOURCE_DIR}/${MAIN_RESOURCE}.in ${CMAKE_SOURCE_DIR}/${MAIN_RESOURCE} @ONLY)

# WIN32 -> aplikacja okienkowa (WinMain zamiast main)
add_executable(AESManager WIN32 ${MAIN_SOURCE} MyVersion.h MyVersion.cpp ${MAIN_RESOURCE}
        ${MAIN_RESOURCE_H} GsAES.cpp GsAES.h GsWinLibrary.cpp GsWinLibrary.h
        AESManager.h GsAboutLibrary.cpp GsAboutLibrary.h)

# Linkujemy biblioteki WinAPI
target_link_libraries(AESManager PRIVATE VERSION COMCTL32 SHLWAPI PATHCCH BCRYPT CRYPT32 GDIPLUS)

message("NEW_VERSION: " ${NEW_VERSION})