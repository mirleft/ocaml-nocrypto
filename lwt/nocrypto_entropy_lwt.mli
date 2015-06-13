(** Rng seeding on {b Lwt/Unix}.

    Calling {!initialize} is enough to bring the RNG into a working state. In
    addition, a background task is set up to periodically reseed the RNG.

    {!initialize} is idempotent as long as {!Nocrypto.Rng.generator} remains
    unswapped, and it is harmless to call it several times.

    Note that while {!initialize} creates a thread and the init phase is fully
    completed only after this thread has completed, the initial seeding is done
    synchronously with the call. This means that there is no need to synchronize
    to the returned thread to simply start using the RNG.

    Therefore, all of the following is correct usage:

    [let _ = Nocrypto_entropy_lwt.initialize ()]

    [let () =
      ignore (Nocrypto_entropy_lwt.initialize ());
      Lwt_main.run (main ())]

    [let () =
      Lwt_main.run (Nocrypto_entropy_lwt.initialize () >>= main)]
*)


type t
(** Represents background reseeding process. *)

val attach : period:int -> ?device:string -> Nocrypto.Rng.g -> t Lwt.t
(** [attach ~period ~device g] instruments the lwt event loop to mix in bytes
    from [device] into [g] whenever external events cause the loop to wake up,
    but no more often than once every [period] seconds.

    [device] defaults to {!Nocrypto_entropy_unix.sys_rng}. *)

val stop : t -> unit Lwt.t
(** Stops the reseeding process associated with [t]. Idempotent. *)

val initialize : unit -> unit Lwt.t
(** [initialize ()] immediately calls {!Nocrypto_entropy_unix.initialize}, which
    primes the global generator {!Nocrypto.Rng.generator}. It then calls
    {!attach} on the global generator.

    If there is a background seeding process started by a previous call, it is
    stopped. *)
