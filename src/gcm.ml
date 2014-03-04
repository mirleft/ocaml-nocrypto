(*
 * Based mostly on NIST 800-38D.
 *)

open Cstruct_

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


let incr32 cs =
  let open Cstruct in
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
    match Cstruct.len cs with
    | 0 -> GF128.to_cstruct y
    | _ ->
        let x = GF128.of_cstruct cs in
        loop h GF128.((x + y) * h) (Cstruct.shift cs 16)
  in
  GF128.(loop (of_cstruct key) zero cs)

let gctr ~cipher ~key ~icb cs =
  let rec loop acc cb cs =
    let y = xor cs (cipher key cb) in
    if len cs > 16 then
      loop (y :: acc) (incr32 cb) (shift cs 16)
    else concat @@ List.rev (y :: acc) in
  loop [] icb cs


let padding cs =
  let p_len n = (16 - (n mod 16)) mod 16 in
  create_with (p_len (len cs)) 0

let bits cs = Int64.of_int (len cs * 8)

let gcm ~cipher ~mode ~key ~iv ?(adata=empty) data =

  let h  = cipher key (of_int64s [0L; 0L]) in

  let j0 = match len iv with
    | 12 -> concat [ iv; of_int32s [1l] ]
    | _  -> ghash ~key:h @@
            concat [ iv; padding iv; of_int64s [0L; bits iv] ] in

  let data' = gctr ~cipher ~key ~icb:(incr32 j0) data in

  let (pdata, cdata) = match mode with
    | `Encrypt -> (data , data')
    | `Decrypt -> (data', data ) in

  let s = ghash ~key:h @@
          concat [ adata ; padding adata ; cdata ; padding cdata ;
                   of_int64s [ bits adata ; bits cdata  ] ] in
  let t = gctr ~cipher ~key ~icb:j0 s in

  (data', t)






let test = [
  ( "00000000000000000000000000000000",
    "",
    "000000000000000000000000") ;
  ( "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "000000000000000000000000" ) ;
  ( "feffe9928665731c6d6a8f9467308308",
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    "cafebabefacedbaddecaf888")
  ]

(* let dotest () =
  let open Block_cipher in
  List.map (fun (key, p, iv) ->
    gcm ~cipher:AES.encrypt
        ~mode:`Encrypt
        ~key:(AES.of_secret (of_hex key))
        ~iv:(of_hex iv)
        (of_hex p))
  test *)

module CheckGF = struct

  let rec range a b = if a > b then [] else a :: range (a + 1) b

  let rec iterate f a = function 0 -> a | n -> iterate f (f a) (pred n)

  let n_cases f n = List.for_all f @@ range 1 n

  let commutes =
    n_cases @@ fun _ ->
      let (a, b) = I128.(rnd(), rnd()) in GF128.(a + b = b + a)

  let distributes =
    n_cases @@ fun _ ->
      let (a, b, c) = I128.(rnd(), rnd(), rnd()) in
      GF128.((a + b) * c = a * c + b * c)

  let order =
    n_cases @@ fun _ ->
      let a = I128.rnd() in
      a = iterate (fun x -> GF128.(x * x)) a 128
end
