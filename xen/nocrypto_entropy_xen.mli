
val attach : Entropy_xen.t -> Nocrypto.Fortuna.g -> unit Lwt.t
(** Start seeding the given generator with the given source. *)

val initialize : unit -> unit Lwt.t
(** Start seeding the current default generator in [Nocrypto.Rng]. *)
