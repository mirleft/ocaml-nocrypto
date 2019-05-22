open Nocrypto
open Uncommon

let a_little = 32
let a_lot =    1024


let sys_rng = "BCryptGenRandom"

external get_random_bytes: unit -> int = "get_random_bytes"

let read_cs n =
    let buf = Bytes.create n in
    let k = get_random_bytes () in
    let cs = Cstruct.create k in
    Cstruct.blit_from_bytes buf 0 cs 0 k;
    cs

let reseed ?(bytes = a_little) ?(device = sys_rng) g =
    let rec feed n =
      if n > 0 then
        let cs = read_cs(n) in
        Rng.reseed ~g cs;
        feed (n - Cstruct.len cs) in
    feed bytes

let initialize () =
    let g = !Rng.generator in
    if not (Rng.seeded (Some g)) then reseed ~bytes:a_lot g
