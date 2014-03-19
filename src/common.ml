
let sign = function
  | 0            -> 0
  | x when x > 0 ->  1
  | _            -> -1

let cdiv x y = x / y + sign (x mod y)

let o f g h = f (g h)

let id x = x

let z_two = Z.of_int 2

module CS = struct

  open Cstruct

  let empty = Cstruct.create 0

  let append cs1 cs2 =
    let l1 = len cs1 and l2 = len cs2 in
    let cs = create (l1 + l2) in
    blit cs1 0 cs 0 l1 ;
    blit cs2 0 cs l1 l2 ;
    cs

  let (<>) = append

  let concat = function
    | []   -> create 0
    | [cs] -> cs
    | css  ->
        let result = create (lenv css) in
        let _ = List.fold_left
          (fun off cs ->
            let n = len cs in
            blit cs 0 result off n ;
            off + n
          ) 0 css in
        result

  let cs_equal cs1 cs2 =
    to_bigarray cs1 = to_bigarray cs2

  let clone ?n cs =
    let n  = match n with
      | None   -> len cs
      | Some n -> n in
    let cs' = create n in
    ( blit cs 0 cs' 0 n ; cs' )

  let xor_into src dst n =
    let open LE in
    let rec loop i = function
      | n when n >= 8 ->
          set_uint64 dst i (Int64.logxor (get_uint64 src i) (get_uint64 dst i));
          loop (i + 8) (n - 8)
      | n when n >= 4 ->
          set_uint32 dst i (Int32.logxor (get_uint32 src i) (get_uint32 dst i));
          loop (i + 4) (n - 4)
      | n when n >= 2 ->
          set_uint16 dst i (get_uint16 src i lxor get_uint16 dst i);
          loop (i + 2) (n - 2)
      | 1 -> set_uint8 dst i (get_uint8 src i lxor get_uint8 dst i)
      | _ -> ()
    in
    loop 0 n

  let xor cs1 cs2 =
    let n  = min (len cs1) (len cs2) in
    let cs = clone ~n cs2 in
    ( xor_into cs1 cs n ; cs )

  let fill cs x =
    for i = 0 to len cs - 1 do set_uint8 cs i x done

  let create_with n x =
    let cs = create n in ( fill cs x ; cs )

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
