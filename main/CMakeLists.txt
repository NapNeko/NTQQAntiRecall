cmake_minimum_required(VERSION 3.12)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project(NapCatWinBootMain)
set(CMAKE_CXX_STANDARD 26)

if(MSVC)
	add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
	add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
endif()
file(GLOB SOURCES "*.cpp")
#/MANIFESTUAC:"level='highestAvailable' uiAccess='true'"
#add_executable (NapCatWinBootMain ${SOURCES})
add_executable (NapCatWinBootMain WIN32 ${SOURCES})
#设置Manifest
# set_target_properties(NapCatWinBootMain PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")