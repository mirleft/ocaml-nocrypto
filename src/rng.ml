
(* XXX Should obsolete this, hate measuring nat's bytes sizes. *)
let gen_z_bytes bytes =
  let rec loop acc = function
    | 0 -> acc
    | n ->
        let i = Random.int 0x100 in
        loop Z.((shift_left acc 8) lor of_int i) (pred n) in
  loop Z.zero bytes

(* XXX unsolved *)
(* [a, b) *)
let gen_z a b =
(*   let rec loop acc = function
    | n when n <= Z.zero -> acc
    | n ->
        let (n_part, n_rest) =
          Z.(n land (of_int 0xff), shift_right n 8) in
        let i    = Random.int Z.(to_int n_part) in
        let acc' = Z.((shift_left acc 8) lor of_int i) in
        loop acc' n_rest in
  loop Z.zero limit *)
  (* fake *)
  let range = Z.(b - a) in
  Z.(of_int64 (Random.int64 (Z.to_int64 range)) mod range + a)
