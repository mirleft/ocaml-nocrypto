
val attach : Entropy_xen.t -> Nocrypto.Fortuna.g -> Entropy_xen.token Lwt.t
(** [attach e g] starts seeding [g] from the entropy provider [e] and returns
 * the token to stop the seeding. *)

val initialize : unit -> unit Lwt.t
(** Starts seeding the current default generator in [Nocrypto.Rng]. Stops the
 * previous seeding process started through the same function. Idempotent as
 * long as the default generator is unchanged. *)

val sources : unit -> Entropy_xen.source list option
(** {!Entropy_xen.source}s set up with the last {!initialize}. *)
