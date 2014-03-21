
type pub  = { e : Z.t ; n : Z.t }

type priv = {
  e : Z.t ; d : Z.t ; n  : Z.t ;
  p : Z.t ; q : Z.t ; dp : Z.t ; dq : Z.t ; q' : Z.t
}

val pub : e:Cstruct.t -> n:Cstruct.t -> pub

val priv : e:Cstruct.t -> d:Cstruct.t -> n:Cstruct.t ->
           p:Cstruct.t -> q:Cstruct.t ->
           dp:Cstruct.t -> dq:Cstruct.t -> q':Cstruct.t ->
           priv

val priv' : e:Cstruct.t -> p:Cstruct.t -> q:Cstruct.t -> priv

val pub_of_priv : priv -> pub

val encrypt   :             key:pub  -> Cstruct.t -> Cstruct.t
val decrypt   : ?g:Rng.g -> key:priv -> Cstruct.t -> Cstruct.t

val generate : ?g:Rng.g -> ?e:Z.t -> int -> priv

val print_key : priv -> unit
