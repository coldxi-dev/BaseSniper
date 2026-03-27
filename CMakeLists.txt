cmake_minimum_required(VERSION 3.21)

project(BaseSniper)

set(CMAKE_BUILD_TYPE Release)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF) 

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -O3 -fvisibility=hidden")

add_subdirectory(utils)

add_subdirectory(memtool)

add_subdirectory(chainer)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ")

add_executable(${CMAKE_PROJECT_NAME}
  ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
  utils
  memtool
  chainer
)
