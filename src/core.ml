
let cs_append cs1 cs2 =
  let (l1, l2) = Cstruct.(len cs1, len cs2) in
  let cs = Cstruct.create (l1 + l2) in
  Cstruct.blit cs1 0 cs 0 l1;
  Cstruct.blit cs2 0 cs l1 l2;
  cs

let cs_xor cs1 cs2 =
  let len = Cstruct.(min (len cs1) (len cs2)) in
  let cs = Cstruct.create len in
  for i = 0 to len - 1 do
    Cstruct.(set_uint8 cs i (get_uint8 cs1 i lxor get_uint8 cs2 i))
  done;
  cs

module Hash : sig
  open Cstruct
  val sha1 : t -> t
  val md5  : t -> t
end
  =
struct

  open Bigarray

  type bytes = (char, int8_unsigned_elt, c_layout) Array1.t

  external sha1_bigarray : bytes -> bytes = "caml_DESU_sha1" 
  external md5_bigarray  : bytes -> bytes = "caml_DESU_md5"

  let sha1 cs =
    Cstruct.of_bigarray (sha1_bigarray (Cstruct.to_bigarray cs))

  let md5 cs =
    Cstruct.of_bigarray (md5_bigarray (Cstruct.to_bigarray cs))
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

  let lpad0 cs =
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

  let hmac_opad = create_with blocksize 0x5c
  let hmac_ipad = create_with blocksize 0x36

  let of_hash_fn hash key message =
    let key' =
      if Cstruct.len key > blocksize then hash key else key in
    let key'' =
      if Cstruct.len key' < blocksize then lpad0 key' else key' in
    let opad = cs_xor key'' hmac_opad
    and ipad = cs_xor key'' hmac_ipad in
    hash (cs_append opad (hash (cs_append ipad message)))

  let sha1 ~key cs = of_hash_fn Hash.sha1 key cs
  let md5  ~key cs = of_hash_fn Hash.md5  key cs
end


(* let random_string () =
  let len = Random.int 1024 in
  let str = String.create len in
  for i = 0 to len - 1 do
    str.[i] <- char_of_int (Random.int 256)
  done;
  str

let head_to_head () =
  let key = random_string ()
  and msg = random_string () in
  let h1 =
    Cstruct.of_string
      Cryptokit.(hash_string (MAC.hmac_sha1 key) msg)
  and h2 =
    Hmac.sha1 ~key:(Cstruct.of_string key)
                  (Cstruct.of_string msg) in
  h1 = h2

let () =
  let cs  = Cstruct.of_string "desu"
  and key = Cstruct.of_string "sekrit" in
  Cstruct.hexdump (Hash.sha1 cs);
  Cstruct.hexdump (Hash.md5 cs);
  Cstruct.hexdump (Hmac.sha1 ~key cs);
  Cstruct.hexdump (Hmac.md5 ~key cs); *)


