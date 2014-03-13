(*
 * Based mostly on NIST 800-38D.
 *)
open Common

module I128 = struct

  open Int64

  let of_cstruct cs =
    Cstruct.BE.(get_uint64 cs 0, get_uint64 cs 8)

  let to_cstruct (a, b) =
    let cs = Cstruct.create 16 in
    Cstruct.BE.( (set_uint64 cs 0 a ; set_uint64 cs 8 b) );
    cs

  let xor (a1, b1) (a2, b2) = (logxor a1 a2, logxor b1 b2)

  let lsr1 (a, b) =
    let a' = shift_right_logical a 1
    and b' = shift_right_logical b 1 in
    match logand a 1L with
    | 0L -> (a', b')
    | _  -> (a', logor b' 0x8000000000000000L)

  let bit (a, b) i =
    let bit' x i = logand 1L (shift_right_logical x (63 - i)) in
    if i < 64 then bit' a i else bit' b (i - 64)

  (* XXX *)
  let rnd () = Random.(Int64.(int64 max_int, int64 max_int))

end

module GF128 = struct

  let r    = (0xe100000000000000L, 0L) (* 11100001 || 0^120 *)
  and zero = (0L, 0L)
  and one  = (0x8000000000000000L, 0L)

  let of_cstruct = I128.of_cstruct
  and to_cstruct = I128.to_cstruct

  let add = I128.xor

  let mul x y =
    let rec loop z v = function
      | 128 -> z
      | i   ->
          let z' = match I128.bit x i with
            | 0L -> z
            | _  -> I128.(add z v)
          and v' = match I128.bit v 127 with
            | 0L -> I128.(lsr1 v)
            | _  -> I128.(add (lsr1 v) r) in
          loop z' v' (succ i) in
    loop zero y 0

  let ( * ) = mul
  and ( + ) = add

  let rec pow x n =
    let rec loop acc b = function
      | 0                  -> acc
      | e when e mod 2 = 1 -> loop (acc * b) b (pred e)
      | e                  -> loop acc (b * b) (e / 2) in
    loop one x n
end

open Cstruct

let incr32 cs =
  let a = BE.get_uint64 cs 0
  and b = BE.get_uint32 cs 8
  and c = BE.get_uint32 cs 12
  and cs' = create 16 in
  BE.set_uint64 cs' 0 a ;
  BE.set_uint32 cs' 8 b ;
  BE.set_uint32 cs' 12 (Int32.succ c) ;
  cs'


let ghash ~key cs =
  let rec loop h y cs =
    match len cs with
    | 0 -> GF128.to_cstruct y
    | _ ->
        let x = GF128.of_cstruct cs in
        loop h GF128.((x + y) * h) (shift cs 16)
  in
  GF128.(loop (of_cstruct key) zero cs)

let gctr ~cipher ~key ~icb cs =
  let rec loop acc cb cs =
    let y = CS.xor cs (cipher key cb) in
    if len cs > 16 then
      loop (y :: acc) (incr32 cb) (shift cs 16)
    else CS.concat @@ List.rev (y :: acc) in
  loop [] icb cs


let padding cs =
  let p_len n = (16 - (n mod 16)) mod 16 in
  CS.create_with (p_len (len cs)) 0

let nbits cs = Int64.of_int (len cs * 8)

let gcm ~cipher ~mode ~key ~iv ?(adata=CS.empty) data =

  let h  = cipher key (CS.of_int64s [0L; 0L]) in

  let j0 = match len iv with
    | 12 -> CS.concat [ iv; CS.of_int32s [1l] ]
    | _  -> ghash ~key:h @@
            CS.concat [ iv; padding iv; CS.of_int64s [0L; nbits iv] ] in

  let data' = gctr ~cipher ~key ~icb:(incr32 j0) data in

  let (pdata, cdata) = match mode with
    | `Encrypt -> (data , data')
    | `Decrypt -> (data', data ) in

  let s = ghash ~key:h @@
          CS.concat [ adata ; padding adata
                    ; cdata ; padding cdata
                    ; CS.of_int64s [ nbits adata ; nbits cdata  ] ]
  in
  let t = gctr ~cipher ~key ~icb:j0 s in

  (data', t)

