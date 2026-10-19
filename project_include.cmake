# `idf.py fingerprint` prints the fingerprint of this project's firmware: the SHA-256 ESP-IDF
# appends to the app image, which is also what the device reports. For a signed
# image that is not the file's last 32 bytes, so scripts/firmware_fingerprint.py walks the image to
# find it. The app is built first.
if(NOT BOOTLOADER_BUILD)
    idf_build_get_property(python PYTHON)
    idf_build_get_property(project_name PROJECT_NAME)

    add_custom_target(fingerprint
        COMMAND ${python} -I "${CMAKE_CURRENT_LIST_DIR}/scripts/firmware_fingerprint.py"
                "${CMAKE_BINARY_DIR}/${project_name}.bin"
        VERBATIM
        USES_TERMINAL
    )
    add_dependencies(fingerprint app)
endif()
