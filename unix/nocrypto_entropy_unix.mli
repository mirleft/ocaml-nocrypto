(** {b RNG} seeding on {b Unix}.

    Calling {!initialize} is enough to bring the RNG into a working state.

    {!initialize} is idempotent as long as {!Nocrypto.Rng.generator} remains
    unswapped, and it is harmless to call it several times.

    Depending on the generator in use, periodic reseeding is advisable for
    long-running services. You might want to keep invoking {!reseed} on
    {!Nocrypto.Rng.generator} (or the generator you are using) with a low
    frequency. If you rely on {b lwt}, check out {!Nocrypto_entropy_lwt}.
*)

val sys_rng : string
(** Detected system RNG device. *)

val reseed : ?bytes:int -> ?device:string -> Nocrypto.Rng.g -> unit
(** [reseed ~bytes ~g] mixes in [bytes] bytes from the system RNG as stored in
    {!sys_rng} into the generator [g].

    [bytes] default to a small value reasonable for periodic reseeding.

    [device] defaults to {!sys_rng}. *)

val initialize : unit -> unit
(** Checks if the current global generator {!Nocrypto.Rng.generator} is already
    seeded. If not, it is seeded from the system RNG device.

    This is the closest thing to {!Random.self_init} and is a good way to prime
    the RNG. *)
