#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
#require "cpuid"
#require "ocb-stubblr.topkg"
open Topkg
open Ocb_stubblr_topkg

let cpuflags = [`SSSE3; `AES; `PCLMULQDQ]

let unix = Conf.with_pkg ~default:true "unix"
let lwt  = Conf.with_pkg ~default:false "lwt"
let xen  = Conf.(key "xen" bool ~absent:false
                 ~doc:"Build Mirage/Xen support.")
let fs   = Conf.(key "freestanding" bool ~absent:false
                 ~doc:"Build Mirage/Solo5 support.")
let mir  = Conf.(key "mirage" bool ~absent:false
                  ~doc:"Build Mirage support.")
let accelerate = Conf.(discovered_key "accelerate" bool
  ~absent:(fun () -> match Cpuid.supports cpuflags with
                     | Ok r -> Ok r | Error _ -> Ok false)
  ~env:"NOCRYPTO_ACCELERATE"
  ~doc:"Enable the use of extended CPU features (SSE3, AES-NI). \
        If unspecified, matches build machine's capabilities.")

let tags = [(accelerate, "accelerate")]

let opams =
  let build = ["ocb-stubblr"; "cpuid"]
  and hacks = [ "zarith-xen"; "mirage-xen"; "mirage-no-xen";
                "zarith-freestanding"; "mirage-solo5"; "mirage-no-solo5" ]
  in [Pkg.opam_file "opam" ~lint_deps_excluding:(Some (build @ hacks))]

let cmd c os files =
  OS.Cmd.run Cmd.(build_cmd c os %% Pkg.ocb_bool_tags c tags %% of_list files)

let build = Pkg.build ~cmd ()

let () =
  Pkg.describe "nocrypto" ~build ~opams @@ fun c ->
    let unix = Conf.value c unix in
    let lwt  = Conf.value c lwt && unix
    and xen  = Conf.value c xen
    and fs   = Conf.value c fs in
    let mir  = Conf.value c mir in
    Ok [ Pkg.clib "src-base/libnocrypto_base_stubs.clib";
         Pkg.mllib "src-base/nocrypto_base.mllib";

         Pkg.clib "src/libnocrypto_stubs.clib";
         Pkg.mllib "src/nocrypto.mllib" ~api:["Nocrypto"];
         Pkg.mllib ~cond:unix "unix/nocrypto_unix.mllib";
         Pkg.mllib ~cond:lwt "lwt/nocrypto_lwt.mllib";
         Pkg.mllib ~cond:mir "mirage/nocrypto_mirage.mllib";

         Pkg.test "tests/testrunner";
         Pkg.test ~run:false "bench/speed";
         mirage ~xen ~fs "src/libnocrypto_stubs.clib";
  ]
