#require "cstruct, zarith, ctypes, ctypes.stubs, sexplib" ;;
#directory "_build/src" ;;
#load "nocrypto.cma";;
#require "oUnit";;
#directory "_build/tests";;
#load "testlib.cma";;

module Top = struct
  let print_z ff n = Format.fprintf ff "%s" Z.(to_string n) ;;
end

#install_printer Top.print_z ;;
