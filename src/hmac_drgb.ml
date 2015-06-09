module Make (H : Hash.T) = struct

  open Uncommon

  type g =
    { mutable k : Cstruct.t
    ; mutable v : Cstruct.t
    }

  let block = H.digest_size

  let (bx00, bx01) = Cs.(b 0x00, b 0x01)

  let create () =
    { k = Cs.create_with H.digest_size 0x00
    ; v = Cs.create_with H.digest_size 0x01
    }

  (* XXX *)
  let seeded ~g:_ = invalid_arg "implement Hmac_drgb.seeded..."
  let accumulate ~g:_ = invalid_arg "implement Hmac_drgb.accumulate..."

  let reseed ~g cs =
    let (k, v) = (g.k, g.v) in
    let k = H.hmac ~key:k @@ Cs.concat [v; bx00; cs] in
    let v = H.hmac ~key:k v in
    let k = H.hmac ~key:k @@ Cs.concat [v; bx01; cs] in
    let v = H.hmac ~key:k v in
    g.k <- k; g.v <- v

  let generate ~g bytes =
    let rec go acc k v = function
      | 0 -> (v, Cs.concat @@ List.rev acc)
      | i -> let v = H.hmac ~key:k v in go (v::acc) k v (pred i) in
    let (v, cs) = go [] g.k g.v (cdiv bytes H.digest_size) in
    g.k <- H.hmac ~key:g.k Cs.(v <+> bx00);
    g.v <- H.hmac ~key:g.k v;
    Cstruct.sub cs 0 bytes
end
