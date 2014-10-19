open OUnit2

open Nocrypto.Uncommon

let hex_of_cs cs =
  let b = Buffer.create 16 in
  Cstruct.hexdump_to_buffer b cs ; Buffer.contents b

let assert_cs_equal ?pp_diff ?msg =
  assert_equal
    ~cmp:Cs.equal
    ~printer:hex_of_cs
    ?pp_diff
    ?msg
