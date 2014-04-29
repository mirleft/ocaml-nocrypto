
open Common
open Algo_types.Block

module type T_ECB = Mode
module type T_CBC = Mode_CBC

let ba_of_cs = Cstruct.to_bigarray


module Modes = struct

  module Base_of ( C : Cipher_raw ) : Cipher_base = struct

    type key = C.ekey * C.dkey

    let of_secret cs = C.(e_of_secret cs, d_of_secret cs)

    let (key_sizes, block_size) = C.(key_sizes, block_size)

    let encrypt ~key: (key, _) plain =
      let cipher = Cstruct.create block_size in
      ( C.encrypt_block ~key plain cipher ; cipher )

    let decrypt ~key: (_, key) cipher =
      let plain = Cstruct.create block_size in
      ( C.decrypt_block ~key cipher plain ; plain )
  end

  module ECB_of ( C : Cipher_raw ) : Mode = struct

    open Cstruct

    type key = C.ekey * C.dkey

    let (key_sizes, block_size) = C.(key_sizes, block_size)

    let of_secret sec = C.(e_of_secret sec, d_of_secret sec)

    let encrypt, decrypt =
      let ecb f key source =
        let rec loop src = function
          | dst when Cs.null dst -> ()
          | dst ->
              f ~key src dst ;
              loop (shift src block_size)
                   (shift dst block_size) in
        let dst = create @@ len source in
        ( loop source dst ; dst ) in
      (fun ~key:(key, _) -> ecb C.encrypt_block key),
      (fun ~key:(_, key) -> ecb C.decrypt_block key)

  end

  module CBC_of ( C : Cipher_raw ) : Mode_CBC = struct

    open Cstruct

    type result = { message : Cstruct.t ; iv : Cstruct.t }
    type key    = C.ekey * C.dkey

    let (key_sizes, block_size) = C.(key_sizes, block_size)

    let of_secret sec = C.(e_of_secret sec, d_of_secret sec)

    let encrypt ~key:(key, _) ~iv plain =
      let rec loop iv = function
        | plain when Cs.null plain -> iv
        | plain ->
            Cs.xor_into iv plain block_size ;
            C.encrypt_block ~key plain plain ;
            loop (sub plain 0 block_size)
                 (shift plain block_size)
      in
      let dst = Cs.clone plain in
      let iv' = loop iv dst in
      { message = dst ; iv = iv' }

    let decrypt ~key:(_, key) ~iv cipher =
      let rec loop iv src = function
        | dst when Cs.null dst -> iv
        | dst ->
            C.decrypt_block ~key src dst ;
            Cs.xor_into iv dst block_size ;
            loop (sub src 0 block_size)
                 (shift src block_size)
                 (shift dst block_size)
      in
      let dst = create @@ len cipher in
      let iv' = loop iv cipher dst in
      { message = dst ; iv = iv' }

  end

  module GCM_of ( C : Cipher_base ) : Mode_GCM = struct

    assert (C.block_size = 16)

    type result = { message : Cstruct.t ; tag : Cstruct.t }
    type key    = C.key

    let of_secret = C.of_secret

    let (key_sizes, block_size) = C.(key_sizes, block_size)

    let encrypt ~key ~iv ?adata cs =
      let (message, tag) =
        Gcm.gcm ~cipher:C.encrypt ~mode:`Encrypt ~key ~iv ?adata cs
      in { message ; tag }

    let decrypt ~key ~iv ?adata cs =
      let (message, tag) =
        Gcm.gcm ~cipher:C.encrypt ~mode:`Decrypt ~key ~iv ?adata cs
      in { message ; tag }

  end

end


module AES = struct

  module Raw : Cipher_raw = struct

    open Native

    type ekey = ba
    type dkey = ba

    let e_of_secret = o aes_create_enc ba_of_cs
    and d_of_secret = o aes_create_dec ba_of_cs

    let key_sizes  = [| 16; 24; 32 |]
    let block_size = 16

    let encrypt_block ~key src dst =
      aes_encrypt_into key (ba_of_cs src) (ba_of_cs dst)

    and decrypt_block ~key src dst =
      aes_decrypt_into key (ba_of_cs src) (ba_of_cs dst)
  end

  module Base = Modes.Base_of (Raw)

  module ECB = Modes.ECB_of (Raw)
  module CBC = Modes.CBC_of (Raw)
  module GCM = Modes.GCM_of (Base)
end


module DES = struct

  module Raw = struct

    open Native

    type ekey = ba
    type dkey = ba

    let e_of_secret k = des3_create_key (ba_of_cs k) 0
    and d_of_secret k = des3_create_key (ba_of_cs k) 1

    let key_sizes  = [| 24 |]
    let block_size = 8

    let encrypt_block ~key src dst =
      des3_xform_into key (ba_of_cs src) (ba_of_cs dst)

    let decrypt_block = encrypt_block

    and transform_blk2 key src dst =
      des3_xform_into2 key (ba_of_cs src) (ba_of_cs dst)
  end

  module Base = Modes.Base_of (Raw)

  module ECB  = Modes.ECB_of (Raw)
  module CBC  = Modes.CBC_of (Raw)
end
