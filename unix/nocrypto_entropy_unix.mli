(** {b RNG} seeding on {b Unix}.

    Calling {!initialize} is enough to bring the RNG into a working state.

    [initialize] is idempotent as long as the default generator is unchanged.
    It is harmless to call it several times.

    If you are using {b lwt}, you should use {!Nocrypto_entropy_lwt} as this
    module allows for continuous reseeding of the RNG.

    Unless you want to recover from an unlikely case of missing system RNG, the
    recommended way to prime the RNG is to invoke [initialize] at the module
    level:

{[
let () = Nocrypto_entropy_unix.initialize ()
]}

*)

val sys_rng : string
(** Detected system RNG device. *)

val reseed : ?bytes:int -> ?device:string -> Nocrypto.Rng.g -> unit
(** [reseed ~bytes ~g] mixes in [bytes] bytes from the system RNG as stored in
    {!sys_rng} into the generator [g].

    [bytes] default to a small value reasonable for periodic reseeding.

    [device] defaults to {!sys_rng}. *)

val initialize : unit -> unit
(** Seeds the current defalt generator from the system RNG device if it is
    currently unseeded.

    This is the closest thing to {!Random.self_init} and is a good way to prime
    the RNG. *)
