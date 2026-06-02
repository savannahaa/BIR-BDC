cmake_minimum_required(VERSION 3.18)
project(kkrt_pdc2_repro LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_LIBOTE_KKRT "Build libOTe KKRT cost benchmark" OFF)

if(ENABLE_LIBOTE_KKRT)
  find_package(libOTe REQUIRED)
  add_executable(libote_kkrt_cost src/libote_kkrt_cost.cpp)
  target_link_libraries(libote_kkrt_cost oc::libOTe)
endif()
