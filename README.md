# mkmetalink

Generates valid Metalink v4 XML and BitTorrent v1 files given a file or directory and one or more web mirror locations

## Install

```sh
go install github.com/chapmanjacobd/mkmetalink@latest
```

## Example

```sh
$ mkmetalink /mnt/d/archive/text/dumps.wikimedia.org/relevance.zip https://example.com/ https://example.com/second_mirror/
Total size: 222.9 MiB, piece size: 256.0 KiB, 1 files
  [1/1] relevance.zip

Generated:
/mnt/d/archive/text/dumps.wikimedia.org/relevance.zip.meta4
/mnt/d/archive/text/dumps.wikimedia.org/relevance.zip.torrent
```

## Help

```sh
Usage: mkmetalink <path> [<mirrors> ...] [flags]

Arguments:
  <path>             File or directory to package.
  [<mirrors> ...]    HTTPS mirrors (if directory: base URLs).

Flags:
  -h, --help                                                   Show context-sensitive help.
      --pgp-key=STRING                                         If set, pass this GPG --local-user (key id) when signing.
  -o, --out-dir=STRING                                         Optional output directory for generated files. Default: input's parent directory.
      --tracker="https://privtracker.com/metalink/announce"    Tracker URL for generated torrent's announce (default privtracker).
```

## See Also

- [RFC 5854 - The Metalink Download Description Format](https://tools.ietf.org/html/rfc5854)
- [BEP 19 - WebSeed - HTTP/FTP Seeding](http://www.bittorrent.org/beps/bep_0019.html)
- [aria2 - Command-line download utility with Metalink support](https://aria2.github.io/)
