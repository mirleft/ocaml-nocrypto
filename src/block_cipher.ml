
open Common

module type Cipher_fn = sig
  type key
  val block_size : int
  val of_secret : Cstruct.t -> key
  val encrypt : key -> Cstruct.t -> Cstruct.t
  val decrypt : key -> Cstruct.t -> Cstruct.t
end

module Mode_ECB ( C : Cipher_fn ) = struct

  let encrypt_ecb, decrypt_ecb =
    let ecb f source =
      let rec loop blocks src = function
        | 0 -> Cstruct_.concat @@ List.rev blocks
        | n -> loop (f src :: blocks)
                    (Cstruct.shift src C.block_size)
                    (n - C.block_size) in
      loop [] source (Cstruct.len source)
    in
    (fun ~key -> ecb (C.encrypt key)),
    (fun ~key -> ecb (C.decrypt key))

end

module Mode_CBC ( C : Cipher_fn ) = struct

  let encrypt_cbc ~key ~iv plain =
    let rec loop blocks iv src = function
      | 0 -> (iv, Cstruct_.concat @@ List.rev blocks)
      | n ->
          let blk = C.encrypt key (Cstruct_.xor src iv) in
          loop (blk :: blocks)
               blk
               (Cstruct.shift src C.block_size)
               (n - C.block_size)
    in
    loop [] iv plain (Cstruct.len plain)

  let decrypt_cbc ~key ~iv cipher =
    let rec loop blocks iv src = function
      | 0 -> (iv, Cstruct_.concat @@ List.rev blocks)
      | n ->
          let blk = C.decrypt key src in
          loop (Cstruct_.xor iv blk :: blocks)
               (Cstruct.sub src 0 C.block_size)
               (Cstruct.shift src C.block_size)
               (n - C.block_size)
    in
    loop [] iv cipher (Cstruct.len cipher)

end

module Mode_GCM ( C : Cipher_fn ) = struct

  assert (C.block_size = 16)

  let encrypt_gcm ~key ~iv ?adata cs =
    Gcm.gcm ~cipher:C.encrypt ~mode:`Encrypt ~key ~iv ?adata cs

  let decrypt_gcm ~key ~iv ?adata cs =
    Gcm.gcm ~cipher:C.encrypt ~mode:`Decrypt ~key ~iv ?adata cs

end

module AES_raw : sig
  type key
  val erase    : key -> unit
  val create_e : Cstruct.t -> key
  val create_d : Cstruct.t -> key
  val encrypt_blk : key -> Cstruct.t -> Cstruct.t -> unit
  val decrypt_blk : key -> Cstruct.t -> Cstruct.t -> unit
end
  =
struct

  let ba_of_cs = Cstruct.to_bigarray

  type key = Native.ba

  let erase = Cstruct_.ba_erase

  let create_e = o Native.aes_create_enc ba_of_cs
  let create_d = o Native.aes_create_dec ba_of_cs

  let encrypt_blk key src dst =
    Native.aes_encrypt_into key (ba_of_cs src) (ba_of_cs dst)

  let decrypt_blk key src dst =
    Native.aes_decrypt_into key (ba_of_cs src) (ba_of_cs dst)
end


module AES_Core = struct

  let block_size = 16

  type key = AES_raw.key * AES_raw.key

  let of_secret cs = AES_raw.(create_e cs, create_d cs)

  let encrypt (e_key, _) plain =
    let cipher = Cstruct.create 16 in
    ( AES_raw.encrypt_blk e_key plain cipher ; cipher )

  let decrypt (_, d_key) cipher =
    let plain = Cstruct.create 16 in
    ( AES_raw.decrypt_blk d_key cipher plain ; plain )

end

module AES = struct
  module AES_ECB = Mode_ECB (AES_Core)
  module AES_CBC = Mode_CBC (AES_Core)
  module AES_GCM = Mode_GCM (AES_Core)

  include AES_Core
  include AES_ECB
  include AES_CBC
  include AES_GCM
end

