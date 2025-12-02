cmake_minimum_required(VERSION 3.16)
project(cmakeTest)
# 设置C++标准
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


add_executable(p1 p1.cpp OkvsTool.cpp SimpleIndex.cpp)
# add_executable(main main.cpp SimpleIndex.cpp  RsOprf.cpp RsPsi.cpp) 


find_package(libOTe REQUIRED)
find_package(OpenSSL REQUIRED)

set(CMAKE_BUILD_TYPE Release)

target_compile_options(p1 PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++17> -lpthread)
# target_compile_options(main PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++17> -lpthread)


target_link_libraries(p1 
    oc::libOTe
    pthread
    OpenSSL::Crypto
    OpenSSL::SSL
)

# target_link_libraries(main 
    oc::libOTe
    pthread
)

# set any other operties like cpp version
# set any other operties like cpp version
