cmake_minimum_required(VERSION 3.15)

project(MPDC_Complete C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output dirs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Download and build QSC
include(FetchContent)
FetchContent_Declare(
  QSC
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSC.git
  GIT_TAG master
)
FetchContent_MakeAvailable(QSC)

# MPDC Static Library
file(GLOB_RECURSE MPDC_SOURCES "Source/MPDC/*.c")
file(GLOB_RECURSE MPDC_HEADERS "Source/MPDC/include/*.h")

add_library(mpdc STATIC ${MPDC_SOURCES} ${MPDC_HEADERS})
target_include_directories(mpdc PUBLIC Source/MPDC)
target_link_libraries(mpdc PUBLIC qsc)

# MPDC Agent
file(GLOB_RECURSE MPDC_AGENT_SOURCES "Source/Agent/*.c")

add_executable(mpdc_agent ${QSMP_AGENT_SOURCES})
target_include_directories(mpdc_agent PRIVATE "Source/Agent")
target_link_libraries(mpdc_agent PRIVATE mpdc)

# MPDC Client
file(GLOB_RECURSE MPDC_CLIENT_SOURCES "Source/Client/*.c")

add_executable(mpdc_client ${MPDC_CLIENT_SOURCES})
target_include_directories(mpdc_client PRIVATE Source/Client)
target_link_libraries(mpdc_client PRIVATE mpdc)

# MPDC DLA
file(GLOB_RECURSE MPDC_DLA_SOURCES "Source/DLA/*.c")

add_executable(mpdc_dla ${MPDC_DLA_SOURCES})
target_include_directories(mpdc_dla PRIVATE Source/DLA)
target_link_libraries(mpdc_dla PRIVATE mpdc)

# MPDC MAS
file(GLOB_RECURSE MPDC_MAS_SOURCES "Source/MAS/*.c")

add_executable(mpdc_mas ${MPDC_MAS_SOURCES})
target_include_directories(mpdc_mas PRIVATE "Source/MAS")
target_link_libraries(mpdc_mas PRIVATE mpdc)

# MPDC RDS
file(GLOB_RECURSE MPDC_RDS_SOURCES "Source/RDS/*.c")

add_executable(mpdc_rds ${MPDC_RDS_SOURCES})
target_include_directories(mpdc_rds PRIVATE "Source/RDS")
target_link_libraries(mpdc_rds PRIVATE mpdc)

# Warnings -Werror
foreach(target mpdc mpdc_agent mpdc_client mpdc_dla mpdc_mas mpdc_rds)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endforeach()
