
open Lwt


let chunk  = 32
and period = 30
and device = "/dev/urandom"

type t = {
  fd : Lwt_unix.file_descr ;
  nd : (unit -> unit) Lwt_sequence.node
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
  lwt fd  = Lwt_unix.(openfile device [O_RDONLY] 0) in
  let buf = Cstruct.create chunk in
  let seed () =
    Lwt_cstruct.(complete (read fd) buf) >|= fun () ->
      Nocrypto.Fortuna.reseed ~g buf in
  lwt () = seed () in
  let nd =
    Lwt_sequence.add_r (background ~period seed) Lwt_main.enter_iter_hooks in
  return { fd; nd }

let stop t =
  Lwt_sequence.remove t.nd ;
  Lwt_unix.close t.fd

let stash = ref None

(* Totally not concurrent. *)
let initialize () =
  lwt () = ( match !stash with Some t -> stop t | None -> return_unit )
  and t  = attach ~period ~device !Nocrypto.Rng.generator in
  return (stash := Some t)
