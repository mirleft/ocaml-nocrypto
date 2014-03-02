
include Cstruct

let append cs1 cs2 =
  let (l1, l2) = Cstruct.(len cs1, len cs2) in
  let cs = Cstruct.create (l1 + l2) in
  Cstruct.blit cs1 0 cs 0 l1;
  Cstruct.blit cs2 0 cs l1 l2;
  cs

let concat css =
  let result =
    Cstruct.create @@
      List.fold_left
        (fun a cs -> a + Cstruct.len cs)
        0 css in
  let _ =
    List.fold_left
      (fun off cs ->
        let n = Cstruct.len cs in
        Cstruct.blit cs 0 result off n ; off + n )
      0 css in
  result

let xor cs1 cs2 =
  let len = Cstruct.(min (len cs1) (len cs2)) in
  let cs = Cstruct.create len in
  for i = 0 to len - 1 do
    Cstruct.(set_uint8 cs i (get_uint8 cs1 i lxor get_uint8 cs2 i))
  done;
  cs

let (<>) = append
