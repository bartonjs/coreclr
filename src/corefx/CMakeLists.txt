
# This portion of the tree is for portions of CoreFX libraries which are best
# suited to having been implemented in native code.
#
# The libraries should disable the "lib" prefix, and use an assembly-style naming format,
# such as System.Security.Cryptography.Native (shared across multiple System.Security.Cryptography.*
# assemblies) or System.Diagnostics.Process.Native (a native interop library for
# System.Diagnostics.Process.dll).

if(CLR_CMAKE_PLATFORM_UNIX)
  add_subdirectory(System.Security.Cryptography.Native)
endif(CLR_CMAKE_PLATFORM_UNIX)
