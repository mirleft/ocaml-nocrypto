open OUnit2

open Nocrypto
open Nocrypto.Uncommon

let hex_of_cs cs =
  let b = Buffer.create 16 in
  Cstruct.hexdump_to_buffer b cs ; Buffer.contents b

let rec blocks_of_cs n cs =
  let open Cstruct in
  if len cs <= n then [ cs ]
  else sub cs 0 n :: blocks_of_cs n (shift cs n)

let rec range a b =
  if a > b then [] else a :: range (succ a) b

let rec times ~n f a =
  if n > 0 then ( ignore (f a) ; times ~n:(pred n) f a )

let sample arr =
  let ix = Rng.Int.gen Array.(length arr) in arr.(ix)

let assert_cs_equal ?pp_diff ?msg =
  assert_equal
    ~cmp:Cstruct.equal
    ~printer:hex_of_cs
    ?pp_diff
    ?msg

let assert_cs_not_equal ~msg cs1 cs2 =
  if Cstruct.equal cs1 cs2 then
    assert_failure @@ msg ^ "\n" ^ hex_of_cs cs1
