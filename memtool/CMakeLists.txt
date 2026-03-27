cmake_minimum_required(VERSION 3.21)

#set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_STANDARD 17)

project(memtool)

file(GLOB_RECURSE FILE_SOURCES 
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

add_library(${PROJECT_NAME} STATIC
  ${FILE_SOURCES}
)

target_include_directories(${PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/
)

target_link_libraries(${PROJECT_NAME} PUBLIC utils)