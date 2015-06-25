(** {b RNG} seeding on {b Mirage/Xen}.

    Calling {{!initialize}initialize} should be enough to get a seeded RNG.

    It is the responsibility of the Mirage platform to set up entropy harvesting
    and seeding of the Nocrypto RNG. There is no need to use this module
    directly.
*)


(** {1 Default generator initialization} *)

val initialize : unit -> unit Lwt.t
(** Starts seeding the current default generator and stops the previous seeding
    process started through the same function. Idempotent as long as the default
    generator is unchanged. *)

(** {1 Interface to Mirage Entropy} *)

val sources : unit -> Entropy_xen.source list option
(** {!Entropy_xen.source}s set up with the last {{!initialize}initialize}. *)

val attach : Entropy_xen.t -> Nocrypto.Rng.g -> Entropy_xen.token Lwt.t
(** [attach e g] starts seeding [g] from the entropy provider [e] and returns
    the token to stop the seeding. *)
