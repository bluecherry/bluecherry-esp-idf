# Fetch the active Python interpreter and project metadata from ESP-IDF
idf_build_get_property(python PYTHON)
idf_build_get_property(project_name PROJECT_NAME)
idf_build_get_property(project_path PROJECT_PATH) # Fetches the project root path
idf_build_get_property(project_ver PROJECT_VER)   # Fetches the project version string

set(INPUT_BIN "${CMAKE_BINARY_DIR}/${project_name}.bin")
set(OUTPUT_OTA "${CMAKE_BINARY_DIR}/${project_name}.ota")

# Pull the secure boot version from the config (Default to 0 if disabled)
set(SECURE_BOOT_VERSION 0)
if("${CONFIG_SECURE_BOOT_V1_ENABLED}")
    set(SECURE_BOOT_VERSION 1)
elseif("${CONFIG_SECURE_BOOT_V2_ENABLED}")
    set(SECURE_BOOT_VERSION 2)
endif()

# Force relative paths to become absolute using the project root directory
set(RESOLVED_SIGNING_KEY "${CONFIG_BLUECHERRY_OTA_SIGNING_KEY}")
if(NOT IS_ABSOLUTE "${RESOLVED_SIGNING_KEY}" AND NOT RESOLVED_SIGNING_KEY MATCHES "^~")
    set(RESOLVED_SIGNING_KEY "${CMAKE_SOURCE_DIR}/${RESOLVED_SIGNING_KEY}")
endif()

# Add custom target to fetch the key handle from the Yubikey
add_custom_target(fetch-key
    COMMAND ${python} "${CMAKE_CURRENT_LIST_DIR}/scripts/fetch_key.py"
            "${RESOLVED_SIGNING_KEY}"
    VERBATIM
    USES_TERMINAL # Crucial for passing the visual PIN prompts to the terminal window
)

# Add custom target to sign the .bin
add_custom_target(sign-ota
	COMMAND ${CMAKE_COMMAND} -E echo "${project_ver}"
    COMMAND ${python} "${CMAKE_CURRENT_LIST_DIR}/scripts/sign_ota_esp.py"
            "${RESOLVED_SIGNING_KEY}"
            "${INPUT_BIN}"
            "${OUTPUT_OTA}"
            "${SECURE_BOOT_VERSION}"
            "${project_ver}"
    WORKING_DIRECTORY "${project_path}" # Forces relative paths to resolve from project root
    VERBATIM
    USES_TERMINAL 
)

# Correct way to ensure 'app' builds before 'sign-ota' runs, avoiding CMP0175 warning
add_dependencies(sign-ota app)

# Friendly hint to the developer after a regular build finishes
add_custom_command(TARGET app POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "-----------------------------------------------------------"
    COMMAND ${CMAKE_COMMAND} -E echo "To package and sign this binary for OTA updates, execute:"
    COMMAND ${CMAKE_COMMAND} -E echo "  idf.py sign-ota"
    COMMAND ${CMAKE_COMMAND} -E echo "-----------------------------------------------------------"
)
