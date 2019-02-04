open NHash

let strings =
  List.map (fun n ->
    let cs = Cstruct.create n in Cstruct.memset cs 0xaa; cs
  ) [10; 100; 1_000; 10_000]

open Unmark

let bench fmt = Format.kasprintf (fun name bms -> bench name bms) fmt

let hgroup hash =
  let e = empty ~hash in
  group (Fmt.strf "%a" NHash.pp_hash hash) [
  group "feed" (strings |> List.map @@ fun cs ->
    bench "%d" (Cstruct.len cs) (fun () -> feed e cs));
  group "feedi" (strings |> List.map @@ fun cs ->
    bench "%d" (Cstruct.len cs) (fun () -> feedi e (fun f -> f cs)));
  group "digest" (strings |> List.map @@ fun cs ->
    bench "%d" (Cstruct.len cs) (fun () -> digest ~hash cs));
  group "digesti" (strings |> List.map @@ fun cs ->
    bench "%d" (Cstruct.len cs) (fun () -> digesti ~hash (fun f -> f cs)));
  ]

let suite = [
  hgroup `MD5;
  hgroup `SHA1;
  hgroup `SHA512;
]

let _ = Unmark_cli.main "hashes" suite
