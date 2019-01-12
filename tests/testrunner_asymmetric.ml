open OUnit2

let () = Nocrypto_entropy_unix.initialize ()

let () =
(*   Nocrypto.Rng.reseed @@ Cstruct.of_string "\001\002\003\004" ; *)
  run_test_tt_main Testlib_asymmetric.suite
