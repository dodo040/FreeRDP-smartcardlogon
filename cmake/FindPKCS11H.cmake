# - Find PKCS11-Helper
# Find the native PKCS11-Helper includes and library
#
#  PKCS11H_INCLUDE_DIR - where to find pkcs11.h, etc.
#  PKCS11H_LIBRARIES   - List of libraries when using PKCS11-Helper.
#  PKCS11H_FOUND       - True if PKCS11-Helper found.


IF (PKCS11H_INCLUDE_DIR AND PKCS11H_LIBRARIES)
  # Already in cache, be silent
  SET(PKCS11H_FIND_QUIETLY TRUE)
ENDIF (PKCS11H_INCLUDE_DIR AND PKCS11H_LIBRARIES)

IF (NOT WIN32)
  FIND_PACKAGE(PkgConfig)
  PKG_CHECK_MODULES(PC_PKCS11H libpkcs11-helper-1)
ENDIF (NOT WIN32)

FIND_PATH(PKCS11H_INCLUDE_DIR pkcs11.h
  HINTS
  ${PC_PKCS11H_INCLUDEDIR}
  ${PC_PKCS11H_INCLUDEDIR}/pkcs11-helper-1.0
#  ${PC_PKCS11H_INCLUDEDIR}
#  ${PC_PKCS11H_INCLUDEDIR}/pkcs11
  ${PC_PKCS11H_INCLUDE_DIRS}
  ${PC_PKCS11H_INCLUDE_DIRS}/pkcs11-helper-1.0
#  ${PC_PKCS11H_INCLUDE_DIRS}
#  ${PC_PKCS11H_INCLUDE_DIRS}/pkcs11
  )

FIND_LIBRARY(PKCS11H_LIBRARY NAMES pkcs11-helper
  HINTS
  ${PC_PKCS11H_LIBDIR}
  ${PC_PKCS11H_LIBRARY_DIRS}
  )

# handle the QUIETLY and REQUIRED arguments and set PKCS11_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(PKCS11H DEFAULT_MSG PKCS11H_INCLUDE_DIR PKCS11H_LIBRARY)

IF(PKCS11H_FOUND)
  SET( PKCS11H_LIBRARIES ${PKCS11H_LIBRARY} )
ELSE(PKCS11H_FOUND)
  SET( PKCS11H_LIBRARIES )
ENDIF(PKCS11H_FOUND)

MARK_AS_ADVANCED( PKCS11H_LIBRARY PKCS11H_INCLUDE_DIR )
