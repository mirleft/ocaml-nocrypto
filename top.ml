#require "cstruct, zarith, sexplib"
#directory "_build/src"
#load "nocrypto.cma"

#require "oUnit"
#directory "_build/tests"
#load "testlib.cma"

#directory "_build/unix"
#load "nocrypto_entropy_unix.cmo"

#install_printer Z.pp_print

open Nocrypto

let _ = Nocrypto_entropy_unix.initialize ()
