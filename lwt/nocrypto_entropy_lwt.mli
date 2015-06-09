type t

val attach : period:int -> device:string -> Nocrypto.Rng.g -> t Lwt.t
(** Arranges for bytes from [device] to be used to reseed [g] at most every
 * [period] seconds. *)

val stop : t -> unit Lwt.t
(** Stops the reseeding process associated with [t]. Idempotent. *)

val initialize : unit -> unit Lwt.t
(** [attach]es a reseeding process to the current default generator in
 * [Nocrypto.Rng], stopping the previous process. Idempotent if the global
 * generator has not been changed. *)
