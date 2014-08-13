open OUnit2

open Nocrypto
open Nocrypto.Uncommon


let rec blocks_of_cs n cs =
  let open Cstruct in
  if len cs <= n then [ cs ]
  else sub cs 0 n :: blocks_of_cs n (shift cs n)

let rec range a b =
  if a > b then [] else a :: range (succ a) b

let rec times ~n f a =
  if n > 0 then ( ignore (f a) ; times ~n:(pred n) f a )

let hex_of_cs cs =
  let b = Buffer.create 16 in
  Cstruct.hexdump_to_buffer b cs ; Buffer.contents b

let sample arr =
  let ix = Rng.Int.gen Array.(length arr) in arr.(ix)


let assert_cs_equal ?pp_diff ?msg =
  assert_equal
    ~cmp:Cs.equal
    ~printer:hex_of_cs
    ?pp_diff
    ?msg

let assert_cs_not_equal ~msg cs1 cs2 =
  if Cs.equal cs1 cs2 then
    assert_failure @@ msg ^ "\n" ^ hex_of_cs cs1


let f1_eq ?msg f (a, b) _ =
  let (a, b) = Cs.(of_hex a, of_hex b) in
  assert_cs_equal ?msg (f a) b

let f1v_eq ?msg f (aa, b) _ =
  let (aa, b) = Cs.(List.map of_hex aa, of_hex b) in
  assert_cs_equal ?msg (f aa) b

let f2_eq ?msg f (a, b, c) =
  f1_eq ?msg (f Cs.(of_hex a)) (b, c)

let cases_of f =
  List.map @@ fun params -> test_case (f params)


(* randomized selfies *)

let random_n_selftest (type a) ~typ (m : a Rng.m) n (bounds : (a * a) list) =
  let module N = (val m) in
  let rec check = function
    | []               -> ()
    | (lo, hi)::bounds ->
        let aux () =
          let x = N.gen_r lo hi in
          if x < lo || x >= hi then assert_failure "range error" in
        times ~n aux () ;
        check bounds
  in
  typ ^ "selftest" >:: fun _ -> check bounds

let ecb_selftest ( m : (module Cipher_block.T_ECB) ) n =
  let module C = ( val m ) in
  let check _ =
    let data  = Rng.generate (C.block_size * 8)
    and key   = C.of_secret @@ Rng.generate (sample C.key_sizes) in
    let data' =
      C.( data |> encrypt ~key |> encrypt ~key
               |> decrypt ~key |> decrypt ~key ) in
    assert_cs_equal ~msg:"ecb mismatch" data data'
  in
  "selftest" >:: times ~n check

let cbc_selftest ( m : (module Cipher_block.T_CBC) ) n  =
  let module C = ( val m ) in
  let (!) f x = (f x).C.message in
  let check _ =
    let data = Rng.generate (C.block_size * 8)
    and iv   = Rng.generate C.block_size
    and key  = C.of_secret @@ Rng.generate (sample C.key_sizes) in
    let data' =
      C.( data |> !(encrypt ~key ~iv) |> !(encrypt ~key ~iv)
               |> !(decrypt ~key ~iv) |> !(decrypt ~key ~iv) )
    in
    assert_cs_equal ~msg:"cbc mismatch" data data'
  in
  "selftest" >:: times ~n check

let xor_selftest n =
  "selftest" >:: times ~n @@ fun _ ->

    let n         = Rng.Int.gen 30 in
    let (a, b, c) = Rng.(generate n, generate n, generate n) in

    let abc  = Cs.(xor (xor a b) c)
    and abc' = Cs.(xor a (xor b c)) in
    let a1   = Cs.(xor abc (xor b c))
    and a2   = Cs.(xor (xor c b) abc) in

    assert_cs_equal ~msg:"assoc" abc abc' ;
    assert_cs_equal ~msg:"invert" a a1 ;
    assert_cs_equal ~msg:"commut" a1 a2


let rsa_selftest ~bits n =
  let _e = Z.of_int 0x10001
  and _3 = Z.of_int 3 in

  "selftest" >:: times ~n @@ fun _ ->

    let e = Z.( if bits < 24 then _3 else _e )

    and msg =
      let size = cdiv bits 8 in
      let cs = Rng.generate size in
      Cstruct.set_uint8 cs 0 0 ;
      Cstruct.(set_uint8 cs 1 @@ max 1 (get_uint8 cs 1)) ;
      cs
    in

    let key = Rsa.(generate ~e bits) in
    let enc = Rsa.(encrypt ~key:(pub_of_priv key) msg) in
    let dec = Rsa.(decrypt ~key enc) in

    let key_s = Sexplib.Sexp.to_string_hum Rsa.(sexp_of_priv key) in
    assert_cs_equal
      ~msg:("failed decryption with:\n" ^ key_s)
      msg dec

let dh_selftest ~bits n =

  "selftest" >:: times ~n @@ fun _ ->

    let p = Dh.gen_group bits in

    let (s1, m1) = Dh.gen_secret p
    and (s2, m2) = Dh.gen_secret p in

    let sh1 = Dh.shared p s1 m2
    and sh2 = Dh.shared p s2 m1 in

    assert_cs_equal ~msg:"shared secret" sh1 sh2

(* Xor *)

let xor_cases =
  cases_of (f2_eq ~msg:"xor" Cs.xor) [
    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c" ,
    "0c 0b 0a 09 08 07 06 05 04 03 02 01 00" ,
    "0c 0a 08 0a 0c 02 00 02 0c 0a 08 0a 0c" ;

    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" ,
    "0f 0e 0d 0c 0b 0a 09 08 07 06 05 04 03 02 01 00" ,
    "0f 0f 0f 0f 0f 0f 0f 0f 0f 0f 0f 0f 0f 0f 0f 0f" ;

    "00 01 02", "00", "00" ;

    "00", "00 01 02", "00" ;
  ]

let f1_blk_eq ?msg ?(n=1) f (x, y) _ =
  let (x, y) = Cs.(of_hex x, of_hex y) in
  let xs     = blocks_of_cs n x in
  assert_cs_equal ?msg (f xs) y

let hash_cases ( m : (module Hash.T) ) ~hash =
  let module H = ( val m ) in
  [ "digest"  >::: cases_of (f1_eq H.digest) hash ;
    "digestv" >::: cases_of (f1_blk_eq H.digestv) hash ;
  ]

let hash_cases_mac ( m : (module Hash.T_MAC) ) ~hash ~mac =
  let module H = ( val m ) in
  [ "digest"  >::: cases_of (f1_eq H.digest) hash ;
    "digestv" >::: cases_of (f1_blk_eq H.digestv) hash ;
    "hmac"    >::: cases_of (f2_eq (fun key -> H.hmac ~key)) mac ;
  ]

(* MD5 *)

let md5_cases =
  hash_cases_mac ( module Hash.MD5 )
  ~hash:[
    "" ,
    "d4 1d 8c d9 8f 00 b2 04 e9 80 09 98 ec f8 42 7e" ;

    "00",
    "93 b8 85 ad fe 0d a0 89 cd f6 34 90 4f d5 9f 71" ;

    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" ,
    "1a c1 ef 01 e9 6c af 1b e0 d3 29 33 1a 4f c2 a8" ;
  ]
  ~mac:[
    "2c 03 ca 51 71 a3 d2 d1 41 71 79 6f c8 b2 6c 54" ,
    "8b bb 87 f4 76 4f ba 6a 55 61 c9 80 d5 35 58 4f
     0a 96 cb 60 49 2b 6e dd 71 a1 1e e5 7a 78 9b 73" ,
    "05 8b 08 41 09 79 8b 56 3d 81 49 1f 5f 82 5b ba" ;

    "2c 03 ca 51 71 a3 d2 d1 41 71 79 6f c8 b2 6c 54
     f0 0d a1 07 6c c9 e4 1f b2 17 ec ad 88 56 a2 6e
     d7 83 c3 3d 85 99 0d 8d c5 8d 03 50 00 e2 6e 80
     0c b5 9a 00 26 fd 15 fd 4c e1 84 9d a5 c6 fa a8
     f7 ef f6 c8 76 73 a3 47 0a d5 5a 5b 56 49 22 ec" ,
    "8b bb 87 f4 76 4f ba 6a 55 61 c9 80 d5 35 58 4f
     0a 96 cb 60 49 2b 6e dd 71 a1 1e e5 7a 78 9b 73" ,
    "61 ac 5c 29 9f e2 18 95 d5 4b eb ff 60 42 91 df" ;

    "2c 03 ca 51 71 a3 d2 d1 41 71 79 6f c8 b2 6c 54
     f0 0d a1 07 6c c9 e4 1f b2 17 ec ad 88 56 a2 6e
     d7 83 c3 3d 85 99 0d 8d c5 8d 03 50 00 e2 6e 80
     0c b5 9a 00 26 fd 15 fd 4c e1 84 9d a5 c6 fa a8" ,
    "8b bb 87 f4 76 4f ba 6a 55 61 c9 80 d5 35 58 4f
     0a 96 cb 60 49 2b 6e dd 71 a1 1e e5 7a 78 9b 73" ,
    "ce 44 c2 a1 c5 46 a7 08 a4 0a 7c f2 5e af b1 33" ;
  ]

(* SHA *)

let sha1_cases =
  hash_cases_mac ( module Hash.SHA1 )
  ~hash:[
    "" ,
    "da 39 a3 ee 5e 6b 4b 0d 32 55 bf ef 95 60 18 90
     af d8 07 09" ;

    "00" ,
    "5b a9 3c 9d b0 cf f9 3f 52 b5 21 d7 42 0e 43 f6
     ed a2 78 4f" ;

    "89 d1 68 64 8d 06 0c f2 ed a1 9a a3 10 56 85 48
     69 84 63 df 13 7c 96 5e b5 7b 23 ec b1 f8 e9 ef" ,
    "00 6f 23 b3 5d 7d 09 78 03 35 68 97 ea 6e e3 3c
     57 b2 11 ca" ;
  ]
  ~mac:[
    "", "",
    "fb db 1d 1b 18 aa 6c 08 32 4b 7d 64 b7 1f b7 63
     70 69 0e 1d" ;

    "9c 64 fc 6a 9a bb 1e 04 43 6d 58 49 3f 0d 30 21
     d6 8f eb a9 67 c0 1f 9f c9 35 dc a5 95 9b 6c 07
     4b 09 c0 39 bb c6 dc da 97 aa c8 ea 88 4e 17 e9
     7c c6 d9 f7 73 70 e0 cb 1d 64 de 6d 57 91 31 b3" ,
    "",
    "f9 b1 39 0f 1d 88 09 1b 1d a4 4a d5 d6 33 28 65
     c2 70 ca da";

    "9c 64 fc 6a 9a bb 1e 04 43 6d 58 49 3f 0d 30 21
     d6 8f eb a9 67 c0 1f 9f c9 35 dc a5 95 9b 6c 07
     4b 09 c0 39 bb c6 dc da 97 aa c8 ea 88 4e 17 e9
     7c c6 d9 f7 73 70 e0 cb 1d 64 de 6d 57 91 31 b3" ,
    "0d 83 e2 e9 b3 98 e2 8b ea e0 59 7f 37 15 95 1a
     4b 4c 3c ce 4b de 15 4f 53 da fb 2f b4 9f 03 ea" ,
    "ca 02 cd 56 77 dc b5 c1 3e de da 34 51 d9 e2 5c
     d9 29 4c 53" ;

    "9c 64 fc 6a 9a bb 1e 04 43 6d 58 49 3f 0d 30 21
     d6 8f eb a9 67 c0 1f 9f c9 35 dc a5 95 9b 6c 07
     4b 09 c0 39 bb c6 dc da 97 aa c8 ea 88 4e 17 e9
     7c c6 d9 f7 73 70 e0 cb 1d 64 de 6d 57 91 31 b3
     8e 17 5f 4e de 38 f4 14 48 bc 74 56 05 7a 3c 3b" ,
    "0d 83 e2 e9 b3 98 e2 8b ea e0 59 7f 37 15 95 1a
     4b 4c 3c ce 4b de 15 4f 53 da fb 2f b4 9f 03 ea" ,
    "7f f9 d5 9e 62 e8 d7 13 91 9f a2 a7 be 64 85 c5
     a0 39 ec 04";
  ]

let sha224_cases =
  hash_cases (module Hash.SHA224)
  ~hash:[
    "" ,
    "d1 4a 02 8c 2a 3a 2b c9 47 61 02 bb 28 82 34 c4
     15 a2 b0 1f 82 8e a6 2a c5 b3 e4 2f" ;

    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" ,
    "52 9d 65 6a 8b c4 13 fe f5 8d a8 2e 1b f0 30 8d
     cf e0 42 9d cd 80 68 7e 69 c9 46 33" ;

    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
     10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
     20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
     30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f",
    "c3 7b 88 a3 52 2d bf 7a c3 0d 1c 68 ea 39 7a c1
     1d 47 73 57 1a ed 01 dd ab 73 53 1e" ;
  ]

let sha256_cases =
  hash_cases (module Hash.SHA256)
  ~hash:[
    "" ,
    "e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24
     27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55" ;

    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" ,
    "be 45 cb 26 05 bf 36 be bd e6 84 84 1a 28 f0 fd
     43 c6 98 50 a3 dc e5 fe db a6 99 28 ee 3a 89 91" ;

    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
     10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
     20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
     30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f",
    "fd ea b9 ac f3 71 03 62 bd 26 58 cd c9 a2 9e 8f
     9c 75 7f cf 98 11 60 3a 8c 44 7c d1 d9 15 11 08"
  ]

let sha384_cases =
  hash_cases (module Hash.SHA384)
  ~hash:[
    "" ,
    "38 b0 60 a7 51 ac 96 38 4c d9 32 7e b1 b1 e3 6a
     21 fd b7 11 14 be 07 43 4c 0c c7 bf 63 f6 e1 da
     27 4e de bf e7 6f 65 fb d5 1a d2 f1 48 98 b9 5b" ;

    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" ,
    "c8 1d f9 8d 9e 6d e9 b8 58 a1 e6 eb a0 f1 a3 a3
     99 d9 8c 44 1e 67 e1 06 26 01 80 64 85 bb 89 12
     5e fd 54 cc 78 df 5f bc ea bc 93 cd 7c 7b a1 3b" ;

    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
     10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
     20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
     30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f
     40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f
     50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f
     60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f
     70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f" ,
    "ca 23 85 77 33 19 12 45 34 11 1a 36 d0 58 1f c3
     f0 08 15 e9 07 03 4b 90 cf f9 c3 a8 61 e1 26 a7
     41 d5 df cf f6 5a 41 7b 6d 72 96 86 3a c0 ec 17"
  ]


let sha512_cases =
  hash_cases (module Hash.SHA512)
  ~hash:[
    "" ,
    "cf 83 e1 35 7e ef b8 bd f1 54 28 50 d6 6d 80 07
     d6 20 e4 05 0b 57 15 dc 83 f4 a9 21 d3 6c e9 ce
     47 d0 d1 3c 5d 85 f2 b0 ff 83 18 d2 87 7e ec 2f
     63 b9 31 bd 47 41 7a 81 a5 38 32 7a f9 27 da 3e" ;

    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" ,
    "da a2 95 be ed 4e 2e e9 4c 24 01 5b 56 af 62 6b
     4f 21 ef 9f 44 f2 b3 d4 0f c4 1c 90 90 0a 6b f1
     b4 86 7c 43 c5 7c da 54 d1 b6 fd 48 69 b3 f2 3c
     ed 5e 0b a3 c0 5d 0b 16 80 df 4e c7 d0 76 24 03" ;

    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
     10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
     20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
     30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f
     40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f
     50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f
     60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f
     70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f" ,
    "1d ff d5 e3 ad b7 1d 45 d2 24 59 39 66 55 21 ae
     00 1a 31 7a 03 72 0a 45 73 2b a1 90 0c a3 b8 35
     1f c5 c9 b4 ca 51 3e ba 6f 80 bc 7b 1d 1f da d4
     ab d1 34 91 cb 82 4d 61 b0 8d 8c 0e 15 61 b3 f7" ;
  ]

let sha2_cases = [
  "sha224" >::: sha224_cases ;
  "sha256" >::: sha256_cases ;
  "sha384" >::: sha384_cases ;
  "sha512" >::: sha512_cases ;
]

(* aes gcm *)

let gcm_cases =
  let open Cipher_block in

  let case ~key ~p ~a ~iv ~c ~t =
    ( AES.GCM.of_secret (Cs.of_hex key),
      Cs.of_hex p, Cs.of_hex a, Cs.of_hex iv, Cs.of_hex c, Cs.of_hex t ) in

  let check (key, p, adata, iv, c, t) _ =
    let open AES.GCM in
    let { message = cdata ; tag = ctag } =
      AES.GCM.encrypt ~key ~iv ~adata p in
    let { message = pdata ; tag = ptag } =
      AES.GCM.decrypt ~key ~iv ~adata cdata
    in
    assert_cs_equal ~msg:"cyphertext" c cdata ;
    assert_cs_equal ~msg:"encryption tag" t ctag  ;
    assert_cs_equal ~msg:"decrypted plaintext" p pdata ;
    assert_cs_equal ~msg:"decryption tag" t ptag
  in

  cases_of check [

    case ~key: "00000000000000000000000000000000"
         ~p:   ""
         ~a:   ""
         ~iv:  "000000000000000000000000"
         ~c:   ""
         ~t:   "58e2fccefa7e3061367f1d57a4e7455a"
    ;
    case ~key: "00000000000000000000000000000000"
         ~p:   "00000000000000000000000000000000"
         ~a:   ""
         ~iv:  "000000000000000000000000"
         ~c:   "0388dace60b6a392f328c2b971b2fe78"
         ~t:   "ab6e47d42cec13bdf53a67b21257bddf"
    ;
    case ~key: "feffe9928665731c6d6a8f9467308308"
         ~p:   "d9313225f88406e5a55909c5aff5269a
                86a7a9531534f7da2e4c303d8a318a72
                1c3c0c95956809532fcf0e2449a6b525
                b16aedf5aa0de657ba637b391aafd255"
         ~a:   ""
         ~iv:  "cafebabefacedbaddecaf888"
         ~c:   "42831ec2217774244b7221b784d0d49c
                e3aa212f2c02a4e035c17e2329aca12e
                21d514b25466931c7d8f6a5aac84aa05
                1ba30b396a0aac973d58e091473f5985"
         ~t:   "4d5c2af327cd64a62cf35abd2ba6fab4"
    ;
    case ~key: "feffe9928665731c6d6a8f9467308308"
         ~p:   "d9313225f88406e5a55909c5aff5269a
                86a7a9531534f7da2e4c303d8a318a72
                1c3c0c95956809532fcf0e2449a6b525
                b16aedf5aa0de657ba637b39"
         ~a:   "feedfacedeadbeeffeedfacedeadbeef
                abaddad2"
         ~iv:  "cafebabefacedbaddecaf888"
         ~c:   "42831ec2217774244b7221b784d0d49c
                e3aa212f2c02a4e035c17e2329aca12e
                21d514b25466931c7d8f6a5aac84aa05
                1ba30b396a0aac973d58e091"
         ~t:   "5bc94fbc3221a5db94fae95ae7121a47"
    ;
    case ~key: "feffe9928665731c6d6a8f9467308308"
         ~p:   "d9313225f88406e5a55909c5aff5269a
                86a7a9531534f7da2e4c303d8a318a72
                1c3c0c95956809532fcf0e2449a6b525
                b16aedf5aa0de657ba637b39"
         ~a:   "feedfacedeadbeeffeedfacedeadbeef
                abaddad2"
         ~iv:  "cafebabefacedbad"
         ~c:   "61353b4c2806934a777ff51fa22a4755
                699b2a714fcdc6f83766e5f97b6c7423
                73806900e49f24b22b097544d4896b42
                4989b5e1ebac0f07c23f4598"
         ~t:   "3612d2e79e3b0785561be14aaca2fccb"
    ;
    case ~key: "feffe9928665731c6d6a8f9467308308"
         ~p:   "d9313225f88406e5a55909c5aff5269a
                86a7a9531534f7da2e4c303d8a318a72
                1c3c0c95956809532fcf0e2449a6b525
                b16aedf5aa0de657ba637b39"
         ~a:   "feedfacedeadbeeffeedfacedeadbeef
                abaddad2"
         ~iv:  "9313225df88406e555909c5aff5269aa
                6a7a9538534f7da1e4c303d2a318a728
                c3c0c95156809539fcf0e2429a6b5254
                16aedbf5a0de6a57a637b39b"
         ~c:   "8ce24998625615b603a033aca13fb894
                be9112a5c3a211a8ba262a3cca7e2ca7
                01e4a9a4fba43c90ccdcb281d48c7c6f
                d62875d2aca417034c34aee5"
         ~t:   "619cc5aefffe0bfa462af43c1699d050"
    ;
    case ~key: "feffe9928665731c6d6a8f9467308308
                feffe9928665731c"
         ~p:   "d9313225f88406e5a55909c5aff5269a
                86a7a9531534f7da2e4c303d8a318a72
                1c3c0c95956809532fcf0e2449a6b525
                b16aedf5aa0de657ba637b39"
         ~a:   "feedfacedeadbeeffeedfacedeadbeef
                abaddad2"
         ~iv:  "cafebabefacedbaddecaf888"
         ~c:   "3980ca0b3c00e841eb06fac4872a2757
                859e1ceaa6efd984628593b40ca1e19c
                7d773d00c144c525ac619d18c84a3f47
                18e2448b2fe324d9ccda2710"
         ~t:   "2519498e80f1478f37ba55bd6d27618c"
    ;
    case ~key: "feffe9928665731c6d6a8f9467308308
                feffe9928665731c6d6a8f9467308308"
         ~p:   "d9313225f88406e5a55909c5aff5269a
                86a7a9531534f7da2e4c303d8a318a72
                1c3c0c95956809532fcf0e2449a6b525
                b16aedf5aa0de657ba637b39"
         ~a:   "feedfacedeadbeeffeedfacedeadbeef
                abaddad2"
         ~iv:  "9313225df88406e555909c5aff5269aa
                6a7a9538534f7da1e4c303d2a318a728
                c3c0c95156809539fcf0e2429a6b5254
                16aedbf5a0de6a57a637b39b"
         ~c:   "5a8def2f0c9e53f1f75d7853659e2a20
                eeb2b22aafde6419a058ab4f6f746bf4
                0fc0c3b780f244452da3ebf1c5d82cde
                a2418997200ef82e44ae7e3f"
         ~t:   "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"
]


(* from SP800-38C_updated-July20_2007.pdf appendix C *)
let ccm_cases =
  let open Cipher_block.AES.CCM in
  let case ~key ~p ~a ~nonce ~c ~maclen =
    ( of_secret ~maclen (Cs.of_hex key),
      Cs.of_hex p, Cs.of_hex a, Cs.of_hex nonce, Cs.of_hex c ) in

  let check (key, p, adata, nonce, c) _ =
    let cip = encrypt ~key ~nonce ~adata p in
    assert_cs_equal ~msg:"encrypt" c cip ;
    match decrypt ~key ~nonce ~adata c with
      | Some x -> assert_cs_equal ~msg:"decrypt" p x
      | None -> assert_failure "decryption broken"
  in

  cases_of check [

    case ~key:    "404142434445464748494a4b4c4d4e4f"
         ~p:      "20212223"
         ~a:      "0001020304050607"
         ~nonce:  "10111213141516"
         ~c:      "7162015b4dac255d"
         ~maclen: 4
    ;
    case ~key:    "40414243 44454647 48494a4b 4c4d4e4f"
         ~p:      "20212223 24252627 28292a2b 2c2d2e2f"
         ~a:      "00010203 04050607 08090a0b 0c0d0e0f"
         ~nonce:  "10111213 14151617"
         ~c:      "d2a1f0e0 51ea5f62 081a7792 073d593d 1fc64fbf accd"
         ~maclen: 6
    ;
    case ~key:    "404142434445464748494a4b4c4d4e4f"
         ~p:      "202122232425262728292a2b2c2d2e2f3031323334353637"
         ~a:      "000102030405060708090a0b0c0d0e0f10111213"
         ~nonce:  "101112131415161718191a1b"
         ~c:      "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951"
         ~maclen: 8
  ]

let suite =

  "All" >::: [

    "RNG extraction" >::: [
      random_n_selftest "int" Rng.int 1000 [
        (1, 2); (0, 129); (7, 136); (0, 536870913);
      ] ;
      random_n_selftest "int32" Rng.int32 1000 [
        (7l, 136l); (0l, 536870913l);
      ] ;
      random_n_selftest "int64" Rng.int64 1000 [
        (7L, 136L); (0L, 536870913L); (0L, 2305843009213693953L);
      ] ;
      random_n_selftest "Z" Rng.z 1000 [
        Z.(of_int 7, of_int 135);
        Z.(of_int 0, of_int 536870913);
        Z.(of_int 0, of_int64 2305843009213693953L)
      ] ;
    ] ;

    "RSA" >::: [
(*       rsa_selftest ~bits:8    1000 ; *)
      rsa_selftest ~bits:16   1000 ;
      rsa_selftest ~bits:128  100  ;
      rsa_selftest ~bits:1024 10   ;
    ] ;

    "DHE" >::: [
      dh_selftest ~bits:16  1000 ;
      dh_selftest ~bits:128 100  ;
    ] ;

    "XOR" >::: [ xor_selftest 300 ; "example" >::: xor_cases ];

    "MD5" >::: md5_cases ;

    "SHA1" >::: sha1_cases ;

    "SHA2" >::: sha2_cases ;

    "3DES-ECB" >::: [ ecb_selftest (module Cipher_block.DES.ECB) 100 ] ;

    "3DES-ECB" >::: [ cbc_selftest (module Cipher_block.AES.CBC) 100 ] ;

    "AES-ECB" >::: [ ecb_selftest (module Cipher_block.AES.ECB) 100 ] ;

    "AES-CBC" >::: [ cbc_selftest (module Cipher_block.AES.CBC) 100 ] ;

    "AES-GCM" >::: gcm_cases ;

    "AES-CCM" >::: ccm_cases
  ]

(*
  pk_wat:
    ((e 3) (d 24667) (n 37399) (p 149) (q 251) (dp 99) (dq 167) (q' 19))
  x_wat:
    "\000\158"
*)

(*
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
end *)
