add_executable(pdc2_bench main.cpp)

target_link_libraries(pdc2_bench volePSI)

if(VOLE_PSI_NO_LTO)
    target_link_options(pdc2_bench PUBLIC "-fno-lto")
endif()

if(MSVC)
    target_compile_options(pdc2_bench PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${VOLE_PSI_STD_VER}>)
else()
    target_compile_options(pdc2_bench PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${VOLE_PSI_STD_VER}>)
endif()
