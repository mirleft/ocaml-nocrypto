
module type T = sig
  type key
  type result = { message : Cstruct.t ; key : key }
  val of_secret : Cstruct.t -> key
  val encrypt_into : key:key -> Cstruct.t -> Cstruct.t -> key
  val decrypt_into : key:key -> Cstruct.t -> Cstruct.t -> key
  val encrypt : key:key -> Cstruct.t -> result
  val decrypt : key:key -> Cstruct.t -> result
end

module ARC4 = struct

  type key = int * int * int array

  type result = { message : Cstruct.t ; key : key }

  let of_secret cs =
    let len = Cstruct.len cs in
    ( if len < 1 || len > 256 then invalid_arg "ARC4: invalid key length" );
    let s = Array.init 256 (fun x -> x) in
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

  let encrypt_into ~key:(i, j, s') cs res =
    if Cstruct.len res < Cstruct.len cs then invalid_arg "ARC4: output buffer too short";
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
          s.(i) <- sj ; s.(j) <- si ;
          let k  = s.((si + sj) land 0xff) in
          Cstruct.(set_uint8 res n (k lxor get_uint8 cs n));
          mix i j (succ n)
    in
    mix i j 0

  let decrypt_into = encrypt_into

  let encrypt ~key cs =
    let res = Cstruct.create (Cstruct.len cs) in
    let key' = encrypt_into ~key cs res in
    { key = key'; message = res }

  let decrypt = encrypt

end
