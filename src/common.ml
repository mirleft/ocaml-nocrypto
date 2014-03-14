
let sign = function
  | 0            -> 0
  | x when x > 0 ->  1
  | _            -> -1

let cdiv x y = x / y + sign (x mod y)

let o f g h = f (g h)

let id x = x

module CS = struct

  open Cstruct

  let empty = Cstruct.create 0

  let append cs1 cs2 =
    let (l1, l2) = (len cs1, len cs2) in
    let cs = create (l1 + l2) in
    blit cs1 0 cs 0 l1;
    blit cs2 0 cs l1 l2;
    cs

  let (<>) = append

  let concat = function
    | []   -> create 0
    | [cs] -> cs
    | css  ->
        let result =
          create @@ List.fold_left (fun a cs -> a + len cs) 0 css in
        let _ =
          List.fold_left
            (fun off cs ->
              let n = len cs in
              blit cs 0 result off n ; off + n )
            0 css in
        result

  let copy cs =
    let n   = len cs in
    let cs' = create n in
    ( blit cs 0 cs' 0 n ; cs' )

  let xor_into src dst =
    for i = 0 to len dst - 1 do
      set_uint8 dst i (get_uint8 src i lxor get_uint8 dst i)
    done

  let xor cs1 cs2 =
    let n  = min (len cs1) (len cs2) in
    let cs = create n in
    for i = 0 to n - 1 do
      set_uint8 cs i (get_uint8 cs1 i lxor get_uint8 cs2 i)
    done;
    cs

  let fill cs x =
    for i = 0 to len cs - 1 do set_uint8 cs i x done

  let create_with n x = let cs = create n in ( fill cs x ; cs )

  let rpad cs size x =
    let l   = len cs
    and cs' = create size in
    assert (size >= l) ;
    blit cs 0 cs' 0 l ;
    for i = l to size - 1 do set_uint8 cs' i x done ;
    cs'

  let lpad cs size x =
    let l   = len cs
    and cs' = create size in
    let i0  = size - l in
    assert (size >= l) ;
    blit cs 0 cs' i0 l ;
    for i = 0 to i0 - 1 do set_uint8 cs' i x done ;
    cs'

  let of_bytes, of_int32s, of_int64s =
    let aux k set xs =
      let cs = create @@ List.length xs * k in
      List.iteri (fun i x -> set cs (i * k) x) xs;
      cs
    in
    (aux 1 set_uint8, aux 4 BE.set_uint32, aux 8 BE.set_uint64)

end
