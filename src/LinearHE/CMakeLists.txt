find_package(SEAL 3.3.2 EXACT REQUIRED)
find_package(OpenMP REQUIRED)
find_package(Eigen3 3.3 REQUIRED NO_MODULE)

add_library(OCEAN-LinearHE
    conv-field.cpp
    utils-HE.cpp
)

target_link_libraries(OCEAN-LinearHE
    PRIVATE
    SCI-utils
    SEAL::seal
    OpenMP::OpenMP_CXX
    PUBLIC
    Eigen3::Eigen
)

if(!APPLE)
    target_compile_options(OCEAN-LinearHE PRIVATE "-fopenmp")
endif()
target_compile_options(OCEAN-LinearHE PUBLIC "-fpermissive")
