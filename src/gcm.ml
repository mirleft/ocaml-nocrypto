(*
 * Based mostly on NIST 800-38D.
 *)
open Uncommon

module I128 = struct

  open Int64

  module I64 = Numeric.Int64

  type t = int64 * int64

  let of_cstruct cs : t =
    Cstruct.BE.(get_uint64 cs 0, get_uint64 cs 8)

  let to_cstruct ((a, b) : t) =
    let cs = Cstruct.create 16 in
    Cstruct.BE.( (set_uint64 cs 0 a ; set_uint64 cs 8 b) );
    cs

  let xor (a1, b1) (a2, b2) = I64.(a1 lxor a2, b1 lxor b2)

  let lsr1 (a, b) =
    let open I64 in
    let a' = a lsr 1 and b' = b lsr 1 in
    match a land 1L with
    | 0L -> (a', b')
    | _  -> (a', b' lor 0x8000000000000000L)

  let bit (a, b) i =
    let x = if i < 64 then I64.(lsr) a (63 - i) else I64.(lsr) b (127 - i)
    in I64.(x land 1L = 1L)

  let byte (a, b) i =
    let x =
      if i < 8 then I64.(lsr) a (8 * (7 - i))
      else I64.(lsr) b (8 * (15 - i))
    in I64.(to_int (x land 0xffL))

  let of_byte x i =
    let x = I64.of_int (x land 0xff) in
    if i < 8 then (I64.(lsl) x (8 * (7 - i)), 0L)
    else (0L, I64.(lsl) x (8 * (15 - i)))

  (* XXX *)
  let rnd () = Random.(Int64.(int64 max_int, int64 max_int))

end

module GF128 = struct

  type t = I128.t

  let r    = (0xe100000000000000L, 0L) (* 11100001 || 0^120 *)
  and zero = (0L, 0L)
  and one  = (0x8000000000000000L, 0L)
  and a1   = (0x4000000000000000L, 0L)

  let of_cstruct = I128.of_cstruct
  and to_cstruct = I128.to_cstruct

  let mul x y =
    let open I128 in
    let rec loop z v = function
      | 128 -> z
      | i   -> loop (if bit x i then xor z v else z)
                    (if bit v 127 then xor (lsr1 v) r else lsr1 v)
                    (succ i)
    in loop zero y 0

  and ( + ) = I128.xor
  let ( * ) = mul

  let pow x n =
    let rec loop acc b = function
      | 0                  -> acc
      | e when e mod 2 = 1 -> loop (acc * b) b (pred e)
      | e                  -> loop acc (b * b) (e / 2) in
    loop one x n

  let a8 = pow a1 8

  type hkey = t array array

  let mtab h : hkey =
    Array.init 16 @@ fun i ->
      let ph = h * pow a8 i in
      Array.init 256 (fun x -> I128.(of_byte x 0) * ph)

  let ( @* ) (t : hkey) x =
    let rec loop acc = function
      | 16 -> acc
      | i  -> loop (t.(i).(I128.byte x i) + acc) (succ i) in
    loop zero 0

end

open Cstruct

let hkey h = GF128.(mtab (of_cstruct h))

let ghash ~h cs =
  let rec loop acc cs =
    match len cs with
    | 0 -> GF128.to_cstruct acc
    | _ ->
        let x = GF128.of_cstruct cs in
        loop GF128.(h @* (x + acc)) (shift cs 16)
  in
  loop GF128.zero cs
