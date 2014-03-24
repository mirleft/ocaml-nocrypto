
open Common
open Algo_types.Block


let ba_of_cs = Cstruct.to_bigarray


module Modes = struct

  module Base_of ( C : Cipher_raw ) : Cipher_base = struct

    type key = C.ekey * C.dkey

    let of_secret cs = C.(e_of_secret cs, d_of_secret cs)

    let block_size = C.block_size

    let encrypt ~key: (e_key, _) plain =
      let cipher = Cstruct.create 16 in
      ( C.encrypt_block e_key plain cipher ; cipher )

    let decrypt ~key: (_, d_key) cipher =
      let plain = Cstruct.create 16 in
      ( C.decrypt_block d_key cipher plain ; plain )
  end

  module ECB_of ( C : Cipher_base ) : Mode = struct

    open Cstruct

    type key = C.key

    let of_secret = C.of_secret

    let encrypt, decrypt =
      let ecb f source =
        let rec loop blocks src = function
          | 0 -> CS.concat @@ List.rev blocks
          | n -> loop (f src :: blocks)
                      (shift src C.block_size)
                      (n - C.block_size) in
        loop [] source (len source)
      in
      (fun ~key -> ecb (C.encrypt ~key)),
      (fun ~key -> ecb (C.decrypt ~key))

  end

  module CBC_of ( C : Cipher_base ) : Mode_CBC = struct

    open Cstruct

    type result = { message : Cstruct.t ; iv : Cstruct.t }

    type key = C.key

    let of_secret = C.of_secret

    let encrypt ~key ~iv plain =
      let rec loop blocks iv src = function
        | 0 -> { iv ; message = CS.concat @@ List.rev blocks }
        | n ->
            let blk = C.encrypt ~key (CS.xor src iv) in
            loop (blk :: blocks)
                blk
                (shift src C.block_size)
                (n - C.block_size)
      in
      loop [] iv plain (len plain)

    let decrypt ~key ~iv cipher =
      let rec loop blocks iv src = function
        | 0 -> { iv ; message = CS.concat @@ List.rev blocks }
        | n ->
            let blk = C.decrypt ~key src in
            loop (CS.xor iv blk :: blocks)
                (sub src 0 C.block_size)
                (shift src C.block_size)
                (n - C.block_size)
      in
      loop [] iv cipher (len cipher)

  end

  module GCM_of ( C : Cipher_base ) : Mode_GCM = struct

    assert (C.block_size = 16)

    type result = { message : Cstruct.t ; tag : Cstruct.t }

    type key = C.key
    let of_secret = C.of_secret

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

    let block_size = 16

    let encrypt_block key src dst =
      aes_encrypt_into key (ba_of_cs src) (ba_of_cs dst)

    and decrypt_block key src dst =
      aes_decrypt_into key (ba_of_cs src) (ba_of_cs dst)
  end

  module Base = Modes.Base_of (Raw)

  module ECB = Modes.ECB_of (Base)
  module CBC = Modes.CBC_of (Base)
  module GCM = Modes.GCM_of (Base)
end


module DES = struct

  module Raw = struct

    open Native

    type ekey = ba
    type dkey = ba

    let e_of_secret k = des3_create_key (ba_of_cs k) 0
    and d_of_secret k = des3_create_key (ba_of_cs k) 1

    let block_size = 8

    let encrypt_block key src dst =
      des3_xform_into key (ba_of_cs src) (ba_of_cs dst)

    let decrypt_block = encrypt_block

    and transform_blk2 key src dst =
      des3_xform_into2 key (ba_of_cs src) (ba_of_cs dst)
  end

  module Base = Modes.Base_of (Raw)

  module ECB  = Modes.ECB_of (Base)
  module CBC  = Modes.CBC_of (Base)
end
