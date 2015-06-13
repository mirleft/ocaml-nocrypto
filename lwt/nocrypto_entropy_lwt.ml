open Lwt
open Nocrypto

let chunk  = 32
and period = 30
and device = Nocrypto_entropy_unix.sys_rng


type t = {
  fd     : Lwt_unix.file_descr ;
  remove : (unit -> unit) Lwt_sequence.node ;
  g      : Rng.g
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

let attach ~period ?(device = device) g =
  Lwt_unix.(openfile device [O_RDONLY] 0) >|= fun fd ->
  let buf = Cstruct.create chunk in
  let seed () =
    Lwt_cstruct.(complete (read fd) buf) >|= fun () -> Rng.reseed ~g buf in
  let remove =
      Lwt_sequence.add_r (background ~period seed) Lwt_main.enter_iter_hooks in
  { g ; fd ; remove }

let stop t =
  Lwt_sequence.remove t.remove ;
  catch (fun () -> Lwt_unix.close t.fd)
    Unix.(function Unix_error (EBADF, _, _) -> return_unit | exn -> fail exn)

let active = ref None
and mx     = Lwt_mutex.create ()

let initialize () =
  Nocrypto_entropy_unix.initialize () ;
  Lwt_mutex.with_lock mx @@ fun () ->
    let g      = !Rng.generator in
    let reg () = attach ~period g >|= fun t -> active := Some t in
    match !active with
    | Some t when t.g == g -> return_unit
    | Some t               -> stop t >>= reg
    | None                 -> reg ()
