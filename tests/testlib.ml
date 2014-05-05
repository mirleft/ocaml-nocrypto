
open OUnit2
open Nocrypto
open Common
open Block



let hex_of_cs cs =
  let b = Buffer.create 16 in
  Cstruct.hexdump_to_buffer b cs ; Buffer.contents b

let assert_cs_equal ?pp_diff ?msg =
  assert_equal
    ~cmp:Cs.equal
    ~printer:hex_of_cs
    ?pp_diff
    ?msg

let assert_cs_not_equal ~msg cs1 cs2 =
  if Cs.equal cs1 cs2 then
    assert_failure @@ msg ^ "\n" ^ hex_of_cs cs1

let f1_eq ~msg f (a, b) _ =
  let (a, b) = Cs.(of_hex a, of_hex b) in
  assert_cs_equal ~msg (f a) b

let f2_eq ~msg f (a, b, c) =
  f1_eq ~msg (f Cs.(of_hex a)) (b, c)

let cases_of f =
  List.map @@ fun params -> test_case (f params)

let rec range a b =
  if a > b then [] else a :: range (succ a) b

let rec times ~n f a =
  if n > 0 then ( ignore (f a) ; times ~n:(pred n) f a )

let sample arr =
  let ix = Rng.Int.gen Array.(length arr) in arr.(ix)

(* randomized selfies *)

let ecb_selftest ( m : (module Block.T_ECB) ) n =
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

let cbc_selftest ( m : (module Block.T_CBC) ) n  =
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

    let key = Rsa.generate ~e `Yes_this_is_debug_session bits in
    let enc = Rsa.encrypt ~key:Rsa.(pub_of_priv key) msg in
    let dec = Rsa.decrypt ~key enc
    in

    let key_s = Rsa.string_of_private_key key in
    assert_cs_equal
      ~msg:("failed decryption with:\n" ^ key_s)
      msg dec

let dh_selftest ~bits n =

  "selftest" >:: times ~n @@ fun _ ->

    let p = DH.gen_group bits in

    let (s1, m1) = DH.gen_secret p
    and (s2, m2) = DH.gen_secret p in

    let sh1 = DH.shared p s1 m2
    and sh2 = DH.shared p s2 m1 in

    assert_cs_equal ~msg:"shared secret" sh1 sh2

(* Xor *)

let xor_cases =
  cases_of (f2_eq ~msg:"xor" Cs.xor) [
    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c" ,
    "0c 0b 0a 09 08 07 06 05 04 03 02 01 00" ,
    "0c 0a 08 0a 0c 02 00 02 0c 0a 08 0a 0c" ;

    "00 01 02", "00", "00" ;

    "00", "00 01 02", "00" ;
  ]


(* MD5 *)

let md5_cases = [

  "digest" >:::
    cases_of
      (f1_eq ~msg:"md5" Hash.MD5.digest) [

      "" ,
      "d4 1d 8c d9 8f 00 b2 04 e9 80 09 98 ec f8 42 7e" ;

      "00",
      "93 b8 85 ad fe 0d a0 89 cd f6 34 90 4f d5 9f 71" ;

      "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" ,
      "1a c1 ef 01 e9 6c af 1b e0 d3 29 33 1a 4f c2 a8" ;
    ] ;

  "hmac" >:::
    cases_of
      (f2_eq ~msg:"md5-hmac" (fun key -> Hash.MD5.hmac ~key)) [

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
    ] ;
  ]


(* aes gcm *)

let gcm_cases =

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


let suite =

  "All" >::: [

    "RSA" >::: [
      rsa_selftest ~bits:16   1000 ;
      rsa_selftest ~bits:128  100  ;
      rsa_selftest ~bits:1024 100  ;
    ] ;

    "DHE" >::: [
      dh_selftest ~bits:16  100 ;
      dh_selftest ~bits:128 100 ;
      dh_selftest ~bits:512 1   ;
    ] ;

    "XOR" >::: [ xor_selftest 300 ; "example" >::: xor_cases ];

    "MD5" >::: md5_cases ;

    "3DES-ECB" >::: [ ecb_selftest (module Block.DES.ECB) 100 ] ;

    "3DES-ECB" >::: [ cbc_selftest (module Block.AES.CBC) 100 ] ;

    "AES-ECB" >::: [ ecb_selftest (module Block.AES.ECB) 100 ] ;

    "AES-CBC" >::: [ cbc_selftest (module Block.AES.CBC) 100 ] ;

    "AES-GCM" >::: gcm_cases

  ]

(*
let pk_wat = Z.( Nocrypto.Rsa.({
  e = of_int 3 ;
  d = of_int 24667 ;
  n = of_int 37399 ;
  p = of_int 149 ;
  q = of_int 251 ;
  dp = of_int 99 ;
  dq = of_int 167 ; q' = of_int 19
}) )

let x_wat = Cstruct.of_string "\000\158"
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
