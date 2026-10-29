# The host test sources, each with its main() renamed (one app, one run),
# plus the X25519 checks that need the target (x25519_qemu.c: the host's
# test_x25519.c uses an __int128 oracle the LX6 does not have).
set(C "${CMAKE_CURRENT_LIST_DIR}/../../../components/tinylink/src/crypto")
set(T "${CMAKE_CURRENT_LIST_DIR}/../../test")
idf_component_register(
    SRCS "app.c" "x25519_qemu.c" "fiat_a.c" "fiat_c.c"
         "${T}/ref/curve25519_donna.c" "${C}/curve25519.c"
         "${T}/test_chacha20.c" "${T}/ref/chacha20_ref.c" "${C}/chacha20.c"
         "${T}/test_chacha20poly1305.c" "${C}/chacha20poly1305.c" "${C}/poly1305_donna.c"
         "${T}/test_poly1305.c"
         "${T}/test_blake2s.c" "${C}/blake2s.c"
         "${T}/test_hkdf_noise.c" "${C}/hkdf_blake2s.c"
         "${T}/test_nacl_box.c" "${C}/nacl_box.c" "${C}/salsa20.c" "${C}/secure_zero.c"
    INCLUDE_DIRS "${C}" "${T}"
    PRIV_REQUIRES freertos)
# Host-suite idioms (unused helpers, %zu-free printf) are not errors here.
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wno-unused-function -Wno-format -Wno-unused-variable)
foreach(pair "chacha20:test_chacha20" "aead:test_chacha20poly1305" "poly:test_poly1305"
             "blake2s:test_blake2s" "hkdf:test_hkdf_noise" "nacl:test_nacl_box")
    string(REPLACE ":" ";" pair "${pair}")
    list(GET pair 0 short)
    list(GET pair 1 file)
    set_source_files_properties("${T}/${file}.c" PROPERTIES COMPILE_DEFINITIONS "main=m_${short}")
endforeach()
# The firmware's -O2 islands (components/tinylink/CMakeLists.txt), so the
# code under test is the code that ships.
set_property(SOURCE "fiat_a.c" "fiat_c.c" "${C}/curve25519.c" "${C}/chacha20.c"
    "${C}/chacha20poly1305.c" "${C}/poly1305_donna.c" "${C}/blake2s.c"
    "${C}/hkdf_blake2s.c" "${C}/salsa20.c" "${C}/nacl_box.c" "${C}/secure_zero.c"
    APPEND PROPERTY COMPILE_OPTIONS -O2)
