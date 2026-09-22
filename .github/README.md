# mkmetalink

mkmetalink creates Metalink v4 files and BitTorrent v1 files from a file or
from a directory. You can add one or more HTTPS mirrors.

## Install

```sh
go install github.com/chapmanjacobd/mkmetalink@latest
```

## Example

Package a single file and give it an HTTPS mirror:

```sh
$ mkmetalink -m https://example.com/ ./dumps.wikimedia.org/relevance.zip
Total size: 222.9 MiB, Metalink piece size: 256.0 KiB, torrent piece size: 256.0 KiB, 1 files
  100.0% 12.4 MiB/s   relevance.zip

Completed in 1.08s (avg 12.4 MiB/s)

Generated:
./dumps.wikimedia.org/relevance.zip.meta4
./dumps.wikimedia.org/relevance.zip.torrent
```

`.meta4` holds the Metalink. `.torrent` holds the torrent.

## Reuse hashes with --modify

`--modify` reuses hashes from an existing Metalink or torrent. Use it when the
file content is unchanged, for example after a rename. mkmetalink does not read
the reused files. Reuse avoids the rehash.

The Metalink and torrent that you import must share the same file stem, and the
`.meta4` and `.torrent` outputs must exist side by side (for example, `A.meta4`
and `A.torrent`). Pass either one to `--modify`. mkmetalink finds the other
file automatically. If only one exists, mkmetalink generates only the matching
output.

### Rename a file without rehashing

To rename file `A` to `B`:

```sh
$ mv A B
$ mkmetalink --modify A.meta4 B
```

or pass the old torrent instead:

```sh
$ mkmetalink --modify A.torrent B
```

Both commands reuse the hashes from `A.meta4` and `A.torrent` and create
`B.meta4` and `B.torrent` without reading `B`.

After you verify the new metadata, delete the old files:

```sh
$ rm A.meta4 A.torrent
```

### Rename a directory without rehashing

```sh
$ mv A B
$ mkmetalink --modify A.torrent B
```

### Generate metadata when the files are not present

With `--modify`, the target file or directory does not have to exist on disk.
mkmetalink takes the file layout and the sizes from the imported metadata and
generates the new files.

If an imported hash cannot be matched to a file carrying at least one expected
hash, the file is dropped from the output. When the remaining files no longer
fit the torrent's piece layout, the torrent output is omitted.

### Match with --ignore-size when the file size changes

`--modify` matches imported metadata by file size. If the file size no longer
matches the metadata, the file is normally rehashed. Use `--ignore-size` to
reuse the hashes by relative path instead, even when the file size differs.

With `--ignore-size`, the size is not trusted. Reused hashes describe the
imported content, not the content of the file on disk.

## Folders / Relative paths

```sh
$ mkmetalink -m https://example.com/live/ ./2026-01-01/
```

The command creates a Metalink that references multiple files. Every file name
is the package-relative path.

```xml
  <file name="2026-01-01/docs.txt">
    <url priority="1">https://example.com/live/2026-01-01/docs.txt</url>
    ...
  </file>
  <file name="2026-01-01/v1/data">
    <url priority="1">https://example.com/live/2026-01-01/v1/data</url>
    ...
  </file>
```

## Help

```sh
Usage: mkmetalink <path> [flags]

Arguments:
  <path>    File or directory to package

Flags:
  -h, --help                   Show context-sensitive help.
      --sign=STRING            Sign the generated Metalink with this GPG
                               --local-user (key id)
      --tracker="https://privtracker.com/metalink/announce"
                               Tracker URL for the generated torrent's announce
                               (default privtracker)
  -o, --out-dir=STRING         Optional output directory for generated files.
                               Default: input file's parent directory or input
                               directory
      --modify=PATH            Reuse hashes from an existing Metalink or
                               torrent. Files match by file size
      --ignore-size            With --modify, reuse hashes when the file size
                               no longer matches the metadata
  -m, --mirrors=MIRRORS,...    HTTPS mirrors (if directory: base URLs)
```

## See Also

- [RFC 5854 - The Metalink Download Description Format](https://tools.ietf.org/html/rfc5854)
- [BEP 19 - WebSeed - HTTP/FTP Seeding](http://www.bittorrent.org/beps/bep_0019.html)
- [aria2 - Command-line download utility with Metalink support](https://aria2.github.io/)

![Piece size calculation](./pieces.png)
