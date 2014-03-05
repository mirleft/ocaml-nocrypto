
open OUnit2
open Nocrypto.Block

let int_of_hex_digit c =
  let open Char in
  let i = code (lowercase c) in
  if i >= code '0' && i <= code '9' then Some (i - code '0') else
  if i >= code 'a' && i <= code 'f' then Some (i - code 'a' + 10)
  else None

let hex str =
  let b = Buffer.create 16 in
  let n = String.length str in
  let rec push st i =
    if i = n then () else
      match int_of_hex_digit str.[i], st with
      | None  , _      -> push st (succ i)
      | Some x, None   -> push (Some x) (succ i)
      | Some x, Some y ->
          Buffer.add_char b @@ char_of_int (x + (y lsl 4)) ;
          push None (succ i)
  in
  push None 0 ;
  Cstruct.of_string (Buffer.contents b)

let hex_of_cs cs =
  let b = Buffer.create 16 in
  Cstruct.hexdump_to_buffer b cs ; Buffer.contents b

let assert_bad_cs ~msg ~want ~have =
  assert_failure @@
  Printf.sprintf "%s:\nwant:%shave:%s"
    msg (hex_of_cs want) (hex_of_cs have)

(* aes gcm *)

let gcm_case ~key ~p ~a ~iv ~c ~t =
  ( AES.of_secret (hex key), hex p, hex a, hex iv, hex c, hex t )


let gcm_check (key, p, adata, iv, c, t) _ =
  let (cdata, ctag) = AES.encrypt_gcm ~key ~iv ~adata p in
  let (pdata, ptag) = AES.decrypt_gcm ~key ~iv ~adata cdata in
  if c <> cdata then
    assert_bad_cs ~msg:"cyphertext" ~want:c ~have:cdata
  else if t <> ctag then
    assert_bad_cs ~msg:"encrypted tag" ~want:t ~have:ctag
  else if p <> pdata then
    assert_bad_cs ~msg:"recovered plaintext" ~want:p ~have:pdata
  else if t <> ptag then
    assert_bad_cs ~msg:"decrypted tag" ~want:t ~have:ptag
  else ()

let gcm_cases = [

  gcm_case ~key: "00000000000000000000000000000000"
           ~p:   ""
           ~a:   ""
           ~iv:  "000000000000000000000000"
           ~c:   ""
           ~t:   "58e2fccefa7e3061367f1d57a4e7455a"
  ;
  gcm_case ~key: "00000000000000000000000000000000"
           ~p:   "00000000000000000000000000000000"
           ~a:   ""
           ~iv:  "000000000000000000000000"
           ~c:   "0388dace60b6a392f328c2b971b2fe78"
           ~t:   "ab6e47d42cec13bdf53a67b21257bddf"
  ;
  gcm_case ~key: "feffe9928665731c6d6a8f9467308308"
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
  gcm_case ~key: "feffe9928665731c6d6a8f9467308308"
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
  gcm_case ~key: "feffe9928665731c6d6a8f9467308308"
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
  gcm_case ~key: "feffe9928665731c6d6a8f9467308308"
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
  gcm_case ~key: "feffe9928665731c6d6a8f9467308308
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
  gcm_case ~key: "feffe9928665731c6d6a8f9467308308
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

    "AES-GCM" >:::
      List.mapi
        (fun i params -> string_of_int i >:: gcm_check params)
        gcm_cases
  ]


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
