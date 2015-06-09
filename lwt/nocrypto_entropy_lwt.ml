open Lwt
open Nocrypto

let chunk  = 32
and period = 30
and device = "/dev/urandom"

type t = {
  fd : Lwt_unix.file_descr ;
  nd : (unit -> unit) Lwt_sequence.node ;
  g  : Rng.g
}

let background ~period f =
  let last   = ref Unix.(gettimeofday ())
  and live   = ref false
  and period = float period in
  fun () ->
    let t1 = !last
    and t2 = Unix.gettimeofday () in
    if (not !live) && (t2 -. t1 >= period) then begin
      last := t2 ;
      live := true ;
      async @@ fun () -> f () >|= fun () -> live := false
    end

let attach ~period ~device g =
  Lwt_unix.(openfile device [O_RDONLY] 0) >>= fun fd ->
  let buf = Cstruct.create chunk in
  let seed () =
    Lwt_cstruct.(complete (read fd) buf) >|= fun () -> Rng.reseed ~g buf in
  seed () >>= fun () -> return {
    g ; fd ; nd =
      Lwt_sequence.add_r (background ~period seed) Lwt_main.enter_iter_hooks
  }

let stop t =
  Lwt_sequence.remove t.nd ;
  Lwt_unix.close t.fd

let active = ref None

(* Totally not concurrent. *)
let initialize () =
  let g = !Rng.generator in
  let register () =
    attach ~period ~device g >|= fun t -> active := Some t in
  match !active with
  | Some t when t.g == g -> return_unit
  | Some t               -> stop t >>= register
  | None                 -> register ()
