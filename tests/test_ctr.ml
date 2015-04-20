
open Nocrypto.Cipher_block


module MyCTR = AES.CTR (Counters.Inc_LE)
let key = MyCTR.of_secret Cstruct.(of_string "abcd1234abcd1234")
and ctr  = Cstruct.of_string "1234abcd1234abcd"
and msg = Cstruct.of_string "fire the missile because now there are some nasties who try to hacked my f*cking security system";;


let _ =
  let _ = Printf.printf "Initial CTR:\t%s \n" (Cstruct.to_string ctr) in
  let _ = Printf.printf "----------------------------------------------------- \n" in
  let _ = Printf.printf "Original:\t%s \n" (Cstruct.to_string msg) in
  let _ = Printf.printf "----------------------------------------------------- \n" in
  let enc_result = MyCTR.encrypt ~key ~ctr:ctr msg in
  let _ = Printf.printf "Encrypted:\t%s \n" (Cstruct.to_string enc_result) in
  let _ = Printf.printf "----------------------------------------------------- \n" in
  let _ = Printf.printf "CTR after encryption:\t%s \n" (Cstruct.to_string ctr) in
  let _ = Printf.printf "----------------------------------------------------- \n" in
  let dec_result = MyCTR.decrypt ~key ~ctr:ctr enc_result in
  let _ = Printf.printf "Decrypted:\t%s \n" (Cstruct.to_string dec_result) in
  let _ = Printf.printf "----------------------------------------------------- \n" in
  let _ = Printf.printf "CTR after decryption:\t%s \n" (Cstruct.to_string ctr) in
  Printf.printf "----------------------------------------------------- \n"
