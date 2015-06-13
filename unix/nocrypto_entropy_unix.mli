(** A module providing RNG seeding on {b Unix}.

    Calling {!initialize} is enough to bring the RNG into a working state.
    Periodic reseeding is advisable for long-running services. If use are using
    {b lwt}, {!Nocrypto_entropy_lwt} can do it for you. *)

val reseed : ?bytes:int -> ?device:string -> ?g:Nocrypto.Rng.g -> unit -> unit
(** [seed ~bytes ~device ~g ()] mixes in [bytes] bytes from the file [device]
    into the generator [g].

    This function works well for periodic reseeding of the RNG.

    [g] defaults to the global generator {!Nocrypto.Rng.generator}.

    [device] is probed for by default and should be the system RNG device.

    [bytes] defaults to a value suitable for reseeding. *)

val initialize : unit -> unit
(** Checks if the current global generator {!Nocrypto.Rng.generator} is already
    seeded. If not, it is seeded from the system RNG device. The function is
    idempotent as long as the global generator hasn't been swapped.

    This is the closest thing to {!Random.self_init} and is a good way to prime
    the RNG. *)
