cmake_minimum_required(VERSION 3.15)
project(vole_psi_demo)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置编译类型为Release
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# 引入libOTe库（假设你已正确安装libOTe）
find_package(libOTe REQUIRED)

# 引入pthread库
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# 添加你的主程序
add_executable(vole_psi main.cpp)

# 链接libOTe
target_link_libraries(vole_psi PRIVATE oc::libOTe Threads::Threads)
