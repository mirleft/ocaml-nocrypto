
(* XXX this module can be made faster by
 * a) doing some stuff in-place; and
 * b) maybe moving some simple blit-like ops to C.
 * The authors are aware of that.
 *)

let cs_append cs1 cs2 =
  let (l1, l2) = Cstruct.(len cs1, len cs2) in
  let cs = Cstruct.create (l1 + l2) in
  Cstruct.blit cs1 0 cs 0 l1;
  Cstruct.blit cs2 0 cs l1 l2;
  cs

let cs_concat css =
  let cs_r =
    Cstruct.create @@
      List.fold_left
        (fun a cs -> a + Cstruct.len cs)
        0 css in
  let _ =
    List.fold_left
      (fun off cs ->
        let n = Cstruct.len cs in
        Cstruct.blit cs 0 cs_r off n ; off + n )
      0 css in
  cs_r

let cs_xor cs1 cs2 =
  let len = Cstruct.(min (len cs1) (len cs2)) in
  let cs = Cstruct.create len in
  for i = 0 to len - 1 do
    Cstruct.(set_uint8 cs i (get_uint8 cs1 i lxor get_uint8 cs2 i))
  done;
  cs

let (<>) = cs_append

module Native = struct
  open Bigarray
  type bytes = (char, int8_unsigned_elt, c_layout) Array1.t

  external sha1 : bytes -> bytes = "caml_nc_sha1"
  external md5  : bytes -> bytes = "caml_nc_md5"
  external aes_create_enc : bytes -> bytes = "caml_nc_aes_create_enc_key"
  external aes_create_dec : bytes -> bytes = "caml_nc_aes_create_dec_key"
  external aes_encrypt_into : int -> bytes -> bytes -> bytes -> unit = "caml_nc_aes_encrypt"
  external aes_decrypt_into : int -> bytes -> bytes -> bytes -> unit = "caml_nc_aes_decrypt"
end

module Hash : sig
  open Cstruct
  val sha1 : t -> t
  val md5  : t -> t
end
  =
struct
  let sha1 cs =
    Cstruct.(of_bigarray (Native.sha1 (to_bigarray cs)))

  let md5 cs =
    Cstruct.(of_bigarray (Native.md5 (to_bigarray cs)))
end

module Hmac : sig
  open Cstruct
  val sha1 : key:t -> t -> t
  val md5  : key:t -> t -> t
end
  =
struct

  (* 64 should be enough for everybody! *)
  let blocksize = 64

  let rpad0 cs =
    let open Cstruct in
    let l   = len cs
    and cs' = create blocksize in
    blit cs 0 cs' 0 l;
    for i = l to blocksize - 1 do set_uint8 cs' i 0 done;
    cs'

  let create_with len x =
    let cs = Cstruct.create len in
    for i = 0 to len - 1 do Cstruct.set_uint8 cs i x done;
    cs

  let opad = create_with blocksize 0x5c
  let ipad = create_with blocksize 0x36

  let of_hash_fn hash key message =
    let key = if Cstruct.len key > blocksize then hash key else key in
    let key = if Cstruct.len key < blocksize then rpad0 key else key in
    let outer = cs_xor key opad
    and inner = cs_xor key ipad in
    hash (outer <> hash (inner <> message))

  let sha1 ~key cs = of_hash_fn Hash.sha1 key cs
  let md5  ~key cs = of_hash_fn Hash.md5  key cs

end

module ARC4 : sig
  open Cstruct
  type key
  val of_secret : t -> key
  val encrypt : key -> t -> key * t
  val decrypt : key -> t -> key * t
end
  =
struct

  type key = int * int * int array

  let of_secret cs =
    let len = Cstruct.len cs in
    let s   = Array.init 256 (fun x -> x) in
    let rec loop j = function
      | 256 -> ()
      | i ->
          let x = Cstruct.get_uint8 cs (i mod len) in
          let si = s.(i) in
          let j = (j + si + x) land 0xff in
          let sj = s.(j) in
          s.(i) <- sj ; s.(j) <- si ;
          loop j (succ i)
    in
    ( loop 0 0 ; (0, 0, s) )

  let encrypt (i, j, s') cs =
    let s   = Array.copy s'
    and len = Cstruct.len cs in
    let res = Cstruct.create len in
    let rec mix i j = function
      | n when n = len -> (i, j, s)
      | n ->
          let i  = succ i land 0xff in
          let si = s.(i) in
          let j  = (j + si) land 0xff in
          let sj = s.(j) in
          let k  = s.((si + sj) land 0xff) in
          s.(i) <- sj ; s.(j) <- si ;
          Cstruct.(set_uint8 res n (k lxor get_uint8 cs n));
          mix i j (succ n)
    in
    (mix i j 0, res)

  let decrypt = encrypt

end

module AES : sig
  open Cstruct
  type key
  val of_secret : t -> key
  val encrypt : key -> t -> t
  val decrypt : key -> t -> t
  val encrypt_ecb : key -> t -> t
  val decrypt_ecb : key -> t -> t
  val encrypt_cbc : key -> t -> t -> t * t
  val decrypt_cbc : key -> t -> t -> t * t
end
  =
struct

  let ba_of_cs = Cstruct.to_bigarray

  type key = int * Native.bytes * Native.bytes

  let of_secret cs =
    let arr = ba_of_cs cs in
    let (e_key, d_key) =
      Native.(aes_create_enc arr, aes_create_dec arr) in
    (Cstruct.len cs, e_key, d_key)

  let encrypt (size, e_key, _) plain =
    let cipher = Cstruct.create 16 in
    Native.aes_encrypt_into size e_key (ba_of_cs plain) (ba_of_cs cipher);
    cipher

  let decrypt (size, _, d_key) cipher =
    let plain = Cstruct.create 16 in
    Native.aes_decrypt_into size d_key (ba_of_cs cipher) (ba_of_cs plain);
    plain

  let encrypt_ecb, decrypt_ecb =
    let ecb f source =
      let rec loop blocks src = function
        | 0 -> cs_concat @@ List.rev blocks
        | n -> loop (f src :: blocks) (Cstruct.shift src 16) (n - 16) in
      loop [] source (Cstruct.len source)
    in
    (fun key -> ecb (encrypt key)), (fun key -> ecb (decrypt key))

  let encrypt_cbc key iv plain =
    let rec loop blocks iv src = function
      | 0 -> (iv, cs_concat @@ List.rev blocks)
      | n ->
          let blk = encrypt key (cs_xor src iv) in
          loop (blk :: blocks)
               blk
               (Cstruct.shift src 16)
               (n - 16)
    in
    loop [] iv plain (Cstruct.len plain)

  let decrypt_cbc key iv cipher =
    let rec loop blocks iv src = function
      | 0 -> (iv, cs_concat @@ List.rev blocks)
      | n ->
          let blk = decrypt key src in
          loop (cs_xor iv blk :: blocks)
               (Cstruct.sub src 0 16)
               (Cstruct.shift src 16)
               (n - 16)
    in
    loop [] iv cipher (Cstruct.len cipher)

end

module AES_dbg = struct

  let of_secret_simple str = AES.of_secret (Cstruct.of_string str)

  let encrypt_simple key str =
    let cs = Cstruct.of_string str in
    let xx = AES.encrypt_ecb key cs in
    Cstruct.hexdump xx;
    Cstruct.to_string xx

  let oneoff sec msg = encrypt_simple (of_secret_simple sec) msg

  let loop sec msg =
    let k   = AES.of_secret (Cstruct.of_string sec)
    and pt0 = Cstruct.of_string msg in
    let ct  = AES.encrypt_ecb k pt0 in
    let pt1 = AES.decrypt_ecb k ct  in
    Cstruct.( hexdump pt0 ; hexdump ct ; hexdump pt1 );
    print_endline (Cstruct.to_string pt1);
    (ct, pt1)
end

