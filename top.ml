#require "cstruct, zarith, sexplib" ;;
#directory "_build/src" ;;
#load "nocrypto.cma";;
#require "oUnit";;
#directory "_build/tests";;
#load "testlib.cma";;

#install_printer Z.pp_print ;;

open Nocrypto

let _ = Rng.reseed Cstruct.(of_string "abvgd")
