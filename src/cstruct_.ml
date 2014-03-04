
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

let copy cs =
  let len = Cstruct.len cs in
  let cs' = Cstruct.create len in
  ( Cstruct.blit cs 0 cs' 0 len ; cs' )

let xor_into src dst =
  for i = 0 to Cstruct.len dst - 1 do
    Cstruct.(set_uint8 dst i (get_uint8 src i lxor get_uint8 dst i))
  done

let xor cs1 cs2 =
  let len = Cstruct.(min (len cs1) (len cs2)) in
  let cs = Cstruct.create len in
  for i = 0 to len - 1 do
    Cstruct.(set_uint8 cs i (get_uint8 cs1 i lxor get_uint8 cs2 i))
  done;
  cs

let fill cs x =
  for i = 0 to Cstruct.len cs - 1 do
    Cstruct.set_uint8 cs i x
  done

let create_with n x =
  let cs = Cstruct.create n in ( fill cs x ; cs )

let rpad cs size x =
  let open Cstruct in
  let l   = len cs in
  let cs' = create size in
  assert (size >= l) ;
  blit cs 0 cs' 0 l ;
  for i = l to size - 1 do set_uint8 cs' i x done ;
  cs'

let lpad cs size x =
  let open Cstruct in
  let l   = len cs in
  let cs' = create size
  and i0  = size - l in
  assert (size >= l) ;
  blit cs 0 cs' i0 l ;
  for i = 0 to i0 - 1 do set_uint8 cs' i x done ;
  cs'

let of_bytes, of_int32s, of_int64s =
  let aux k set xs =
    let cs = Cstruct.create (List.length xs * k) in
    List.iteri (fun i x -> set cs (i * k) x) xs;
    cs
  in
  (aux 1 set_uint8, aux 4 BE.set_uint32, aux 8 BE.set_uint64)

let empty = Cstruct.create 0

let (<>) = append

