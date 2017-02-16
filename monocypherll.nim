{.compile: "monocypher.c".}

##  Constant time equality verification
##  returns 0 if it matches, something else otherwise.

proc crypto_memcmp*(p1: ptr uint8; p2: ptr uint8; n: csize): cint {.cdecl,
    importc: "crypto_memcmp".}
## //////////////
## / Chacha20 ///
## //////////////

type
  crypto_chacha_ctx* = object
    input*: array[16, uint32] ##  current input, unencrypted
    random_pool*: array[64, uint8] ##  last input, encrypted
    pool_index*: uint8       ##  pointer to random_pool
  

proc crypto_chacha20_H*(`out`: array[32, uint8]; key: array[32, uint8];
                       `in`: array[16, uint8]) {.cdecl,
    importc: "crypto_chacha20_H".}
proc crypto_chacha20_init*(ctx: ptr crypto_chacha_ctx; key: array[32, uint8];
                          nonce: array[8, uint8]) {.cdecl,
    importc: "crypto_chacha20_init".}
proc crypto_chacha20_Xinit*(ctx: ptr crypto_chacha_ctx; key: array[32, uint8];
                           nonce: array[24, uint8]) {.cdecl,
    importc: "crypto_chacha20_Xinit".}
proc crypto_chacha20_encrypt*(ctx: ptr crypto_chacha_ctx; plain_text: ptr uint8;
                             cipher_text: ptr uint8; message_size: csize) {.cdecl,
    importc: "crypto_chacha20_encrypt".}
proc crypto_chacha20_random*(ctx: ptr crypto_chacha_ctx; cipher_text: ptr uint8;
                            message_size: csize) {.cdecl,
    importc: "crypto_chacha20_random".}
## ///////////////
## / Poly 1305 ///
## ///////////////

type
  crypto_poly1305_ctx* = object
    r*: array[4, uint32]
    h*: array[5, uint32]
    c*: array[5, uint32]
    pad*: array[5, uint32]
    c_index*: csize


proc crypto_poly1305_init*(ctx: ptr crypto_poly1305_ctx; key: array[32, uint8]) {.
    cdecl, importc: "crypto_poly1305_init".}
proc crypto_poly1305_update*(ctx: ptr crypto_poly1305_ctx; m: ptr uint8; bytes: csize) {.
    cdecl, importc: "crypto_poly1305_update".}
proc crypto_poly1305_finish*(ctx: ptr crypto_poly1305_ctx; mac: array[16, uint8]) {.
    cdecl, importc: "crypto_poly1305_finish".}
proc crypto_poly1305_auth*(mac: array[16, uint8]; msg: ptr uint8;
                          msg_length: csize; key: array[32, uint8]) {.cdecl,
    importc: "crypto_poly1305_auth".}
## //////////////
## / Blake2 b ///
## //////////////

type
  crypto_blake2b_ctx* = object
    buf*: array[128, uint8]   ##  input buffer
    hash*: array[8, uint64]   ##  chained state
    input_size*: array[2, uint64] ##  total number of bytes
    c*: uint8                ##  pointer for buf[]
    output_size*: uint8      ##  digest size
  

proc crypto_blake2b_general_init*(ctx: ptr crypto_blake2b_ctx; outlen: csize;
                                 key: ptr uint8; keylen: csize) {.cdecl,
    importc: "crypto_blake2b_general_init".}
proc crypto_blake2b_init*(ctx: ptr crypto_blake2b_ctx) {.cdecl,
    importc: "crypto_blake2b_init".}
proc crypto_blake2b_update*(ctx: ptr crypto_blake2b_ctx; `in`: ptr uint8;
                           inlen: csize) {.cdecl, importc: "crypto_blake2b_update".}
proc crypto_blake2b_final*(ctx: ptr crypto_blake2b_ctx; `out`: ptr uint8) {.cdecl,
    importc: "crypto_blake2b_final".}
proc crypto_blake2b_general*(`out`: ptr uint8; outlen: csize; key: ptr uint8;
                            keylen: csize; `in`: ptr uint8; inlen: csize) {.cdecl,
    importc: "crypto_blake2b_general".}
  ##  digest
  ##  optional secret
proc crypto_blake2b*(`out`: array[64, uint8]; `in`: ptr uint8; inlen: csize) {.cdecl,
    importc: "crypto_blake2b".}
## //////////////
## / Argon2 i ///
## //////////////

proc crypto_argon2i*(tag: ptr uint8; tag_size: uint32; password: ptr uint8;
                    password_size: uint32; salt: ptr uint8; salt_size: uint32;
                    key: ptr uint8; key_size: uint32; ad: ptr uint8;
                    ad_size: uint32; work_area: pointer; nb_blocks: uint32;
                    nb_iterations: uint32) {.cdecl, importc: "crypto_argon2i".}
  ##  >= 4
  ##  >= 8
  ##  >= 8
## /////////////
## / X-25519 ///
## /////////////

proc crypto_x25519*(shared_secret: array[32, uint8];
                   your_secret_key: array[32, uint8];
                   their_public_key: array[32, uint8]) {.cdecl,
    importc: "crypto_x25519".}
proc crypto_x25519_public_key*(public_key: array[32, uint8];
                              secret_key: array[32, uint8]) {.cdecl,
    importc: "crypto_x25519_public_key".}
## /////////////
## / Ed25519 ///
## /////////////

proc crypto_ed25519_public_key*(public_key: array[32, uint8];
                               secret_key: array[32, uint8]) {.cdecl,
    importc: "crypto_ed25519_public_key".}
# proc crypto_ed25519_sign*(signature: array[64, uint8];
#                          secret_key: array[32, uint8]; message: ptr uint8;
#                          message_size: csize) {.cdecl,
#     importc: "crypto_ed25519_sign".}


proc crypto_ed25519_sign*(signature: array[64, uint8];
                         secret_key: array[32, uint8];
                         message: ptr uint8;
                         message_size: csize) {.cdecl, importc: "crypto_ed25519_sign".}


# proc crypto_ed25519_sign*(signature: array[64, uint8];
#                          secret_key: array[32, uint8]; message: ptr openarray[uint8];
#                          message_size: csize) {.cdecl,
#     importc: "crypto_ed25519_sign".}

proc crypto_ed25519_check*(signature: array[64, uint8];
                          public_key: array[32, uint8]; message: ptr uint8;
                          message_size: csize): cint {.cdecl,
    importc: "crypto_ed25519_check".}
# proc crypto_ed25519_check*(signature: array[64, uint8];
#                           public_key: array[32, uint8]; message: ptr openarray[uint8];
#                           message_size: csize): cint {.cdecl,
#     importc: "crypto_ed25519_check".}

## //////////////////////////////
## / Authenticated encryption ///
## //////////////////////////////

proc crypto_ae_lock_detached*(mac: array[16, uint8]; ciphertext: ptr uint8;
                             key: array[32, uint8]; nonce: array[24, uint8];
                             plaintext: ptr uint8; text_size: csize) {.cdecl,
    importc: "crypto_ae_lock_detached".}
proc crypto_ae_unlock_detached*(plaintext: ptr uint8; key: array[32, uint8];
                               nonce: array[24, uint8]; mac: array[16, uint8];
                               ciphertext: ptr uint8; text_size: csize): cint {.
    cdecl, importc: "crypto_ae_unlock_detached".}
proc crypto_ae_lock*(box: ptr uint8; key: array[32, uint8];
                    nonce: array[24, uint8]; plaintext: ptr uint8;
                    text_size: csize) {.cdecl, importc: "crypto_ae_lock".}
  ##  text_size + 16
proc crypto_ae_unlock*(plaintext: ptr uint8; key: array[32, uint8];
                      nonce: array[24, uint8]; box: ptr uint8; text_size: csize): cint {.
    cdecl, importc: "crypto_ae_unlock".}
  ##  text_size + 16
## /////////////////////////////////////////
## / Public key authenticated encryption ///
## /////////////////////////////////////////

proc crypto_lock_key*(shared_key: array[32, uint8];
                     your_secret_key: array[32, uint8];
                     their_public_key: array[32, uint8]) {.cdecl,
    importc: "crypto_lock_key".}
proc crypto_lock_detached*(mac: array[16, uint8]; ciphertext: ptr uint8;
                          your_secret_key: array[32, uint8];
                          their_public_key: array[32, uint8];
                          nonce: array[24, uint8]; plaintext: ptr uint8;
                          text_size: csize) {.cdecl,
    importc: "crypto_lock_detached".}
proc crypto_unlock_detached*(plaintext: ptr uint8;
                            your_secret_key: array[32, uint8];
                            their_public_key: array[32, uint8];
                            nonce: array[24, uint8]; mac: array[16, uint8];
                            ciphertext: ptr uint8; text_size: csize): cint {.cdecl,
    importc: "crypto_unlock_detached".}
proc crypto_lock*(box: ptr uint8; your_secret_key: array[32, uint8];
                 their_public_key: array[32, uint8]; nonce: array[24, uint8];
                 plaintext: ptr uint8; text_size: csize) {.cdecl,
    importc: "crypto_lock".}
  ##  text_size + 16
proc crypto_unlock*(plaintext: ptr uint8; your_secret_key: array[32, uint8];
                   their_public_key: array[32, uint8]; nonce: array[24, uint8];
                   box: ptr uint8; text_size: csize): cint {.cdecl,
    importc: "crypto_unlock".}
  ##  text_size + 16
## /////////////////////////////////////
## / Anonymous public key encryption ///
## /////////////////////////////////////

proc crypto_anonymous_lock*(box: ptr uint8; random_secret_key: array[32, uint8];
                           their_public_key: array[32, uint8];
                           plaintext: ptr uint8; text_size: csize) {.cdecl,
    importc: "crypto_anonymous_lock".}
  ##  text_size + 48
proc crypto_anonymous_unlock*(plaintext: ptr uint8;
                             your_secret_key: array[32, uint8]; box: ptr uint8;
                             text_size: csize): cint {.cdecl,
    importc: "crypto_anonymous_unlock".}
  ##  text_size + 48