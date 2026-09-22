package main

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackpal/bencode-go"
)

func TestCalculatePieceSize(t *testing.T) {
	tests := []struct {
		total    int64
		expected int64
	}{
		{0, P_MIN},
		{1024, P_MIN},
		{100 * 1024 * 1024, 256 * 1024}, // 100MiB -> 256KiB
		{10 * 1024 * 1024 * 1024, 4 * 1024 * 1024},    // 10GiB -> 4MiB (it used to be P_CAP, but N_THRESHOLD might push it higher)
		{100 * 1024 * 1024 * 1024, 16 * 1024 * 1024},  // 100GiB / 7500 pieces ~= 13.3MiB -> stepped to 16MiB
		{1024 * 1024 * 1024 * 1024, 64 * 1024 * 1024}, // 1TiB / 7500 pieces ~= 133MiB -> capped at 64MiB
	}

	for _, tt := range tests {
		got := calculatePieceSize(tt.total)
		if got != tt.expected {
			t.Errorf("calculatePieceSize(%d) = %d; want %d", tt.total, got, tt.expected)
		}
	}
}

func TestMultiHasher(t *testing.T) {
	pieceSize := int64(4) // very small for testing
	mh := NewMultiHasher(pieceSize, pieceSize)

	// File 1: "abcd" (exactly 1 piece)
	mh.StartFile("file1.txt")
	mh.Write([]byte("abcd"))
	res1 := mh.EndFile()

	if res1.Size != 4 {
		t.Errorf("res1 size = %d; want 4", res1.Size)
	}
	if len(res1.SHA256PieceHashes) != 1 {
		t.Errorf("res1 piece count = %d; want 1", len(res1.SHA256PieceHashes))
	}

	// File 2: "efghi" (1 full piece + 1 partial piece)
	mh.StartFile("file2.txt")
	mh.Write([]byte("efgh"))
	mh.Write([]byte("i"))
	res2 := mh.EndFile()

	if res2.Size != 5 {
		t.Errorf("res2 size = %d; want 5", res2.Size)
	}
	if len(res2.SHA256PieceHashes) != 2 {
		t.Errorf("res2 piece count = %d; want 2", len(res2.SHA256PieceHashes))
	}

	mh.Finalize()

	// Torrent pieces (SHA-1)
	// Piece 1: "abcd"
	// Piece 2: "efgh"
	// Piece 3: "i"
	torrentPieces := mh.GetTorrentPieces()
	if len(torrentPieces) != 3*20 {
		t.Errorf("torrent pieces length = %d; want %d", len(torrentPieces), 3*20)
	}
}

func TestEscapeURLPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"file.txt", "file.txt"},
		{"folder/file name.zip", "folder/file%20name.zip"},
		{"tags/v1.0/release.tar.gz", "tags/v1.0/release.tar.gz"},
		{"weird & characters.txt", "weird%20&%20characters.txt"},
	}

	for _, tt := range tests {
		got := escapeURLPath(tt.input)
		if got != tt.expected {
			t.Errorf("escapeURLPath(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestMetalinkValidity(t *testing.T) {
	// Mock some metadata
	meta := Metalink{
		XMLNs:   "urn:ietf:params:xml:ns:metalink",
		Version: "4.0",
		Files: []MetalinkFile{
			{
				Name: "test.bin",
				Size: 10,
				Hash: MetaHash{Type: "sha-256", Value: "916f0027c57591d1e1388d40733544a631bf2a7d88598c099309605470d0473a"},
				Pieces: MetaPieces{
					Type:   "sha-256",
					Length: 1024,
					Hashes: []MetaPieceHash{{Type: "sha-256", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
				},
			},
		},
	}

	buf, err := xml.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Basic validation of the XML output
	xmlStr := string(buf)
	if !strings.Contains(xmlStr, `xmlns="urn:ietf:params:xml:ns:metalink"`) {
		t.Errorf("Metalink missing namespace")
	}
	if !strings.Contains(xmlStr, `version="4.0"`) {
		t.Errorf("Metalink missing version")
	}

	// Round-trip test
	var r Metalink
	if err := xml.Unmarshal(buf, &r); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if r.XMLNs != meta.XMLNs || r.Version != meta.Version {
		t.Errorf("Round-trip failed: got xmlns=%s version=%s", r.XMLNs, r.Version)
	}
	if len(r.Files) != 1 || r.Files[0].Name != "test.bin" {
		t.Errorf("Round-trip failed: file data corrupted")
	}
}

func TestLoadImportedHashes(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "import-*.meta4")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := `<?xml version="1.0" encoding="UTF-8"?>
<metalink xmlns="urn:ietf:params:xml:ns:metalink">
  <file name="oldname.bin">
    <size>1234</size>
    <hash type="sha-256">916f0027c57591d1e1388d40733544a631bf2a7d88598c099309605470d0473a</hash>
    <pieces type="sha-256" length="1024">
      <hash>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</hash>
    </pieces>
  </file>
  <file name="duplicate_size.bin">
    <size>555</size>
    <hash type="sha-256">aaaa</hash>
  </file>
  <file name="another_duplicate.bin">
    <size>555</size>
    <hash type="sha-256">bbbb</hash>
  </file>
</metalink>`
	if _, err := tmpFile.Write([]byte(content)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	imp, err := loadReusableMetadata(tmpFile.Name())
	if err != nil {
		t.Fatalf("loadReusableMetadata failed: %v", err)
	}
	hashes := imp.HashResults

	if len(hashes) != 1 {
		t.Errorf("Expected 1 unique hash (excluding duplicates), got %d", len(hashes))
	}

	// The file list must retain every entry, including same-size collisions
	// that were dropped from the size-keyed hash map.
	if len(imp.MetaFiles) != 3 {
		t.Errorf("Expected 3 files in metadata listing, got %d", len(imp.MetaFiles))
	}

	// Colliding same-size files must remain resolvable by relative path.
	if len(imp.MetaByRel) != 3 {
		t.Fatalf("Expected 3 path-indexed entries, got %d", len(imp.MetaByRel))
	}
	for _, key := range []string{"oldname.bin", "duplicate_size.bin", "another_duplicate.bin"} {
		if _, ok := imp.MetaByRel[key]; !ok {
			t.Errorf("Expected path-indexed entry %q", key)
		}
	}
	if imp.MetaByRel["duplicate_size.bin"].FileSHA256 != "aaaa" ||
		imp.MetaByRel["another_duplicate.bin"].FileSHA256 != "bbbb" {
		t.Errorf("Path-indexed entries lost their distinct hashes: %+v", imp.MetaByRel)
	}

	res, ok := hashes[1234]
	if !ok {
		t.Errorf("Expected size 1234 to be present")
	}
	if res.FileSHA256 != "916f0027c57591d1e1388d40733544a631bf2a7d88598c099309605470d0473a" {
		t.Errorf("Wrong hash imported")
	}
	if len(res.SHA256PieceHashes) != 1 || res.SHA256PieceHashes[0] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("Piece hashes not imported correctly")
	}

	// Verify size 555 was ignored due to collision
	if _, ok := hashes[555]; ok {
		t.Errorf("Size 555 should have been ignored due to collision")
	}
}

func TestLoadReusableMetadataTorrent(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "torrent-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dummySHA1 := "12345678901234567890" // 20 bytes
	tor := Torrent{
		Info: TorrentInfo{
			Name:        "test-dist",
			PieceLength: 16384,
			Files: []TorrentFileInfo{
				{
					Length: 9999,
					Path:   []string{"oldname.bin"},
				},
			},
			Pieces: dummySHA1,
		},
	}

	torPath := filepath.Join(tmpDir, "test.torrent")
	f, err := os.Create(torPath)
	if err != nil {
		t.Fatalf("failed to create torrent file: %v", err)
	}
	if err := bencode.Marshal(f, tor); err != nil {
		f.Close()
		t.Fatalf("failed to marshal torrent: %v", err)
	}
	f.Close()

	// Load using the base name (no extension)
	imp, err := loadReusableMetadata(filepath.Join(tmpDir, "test"))
	if err != nil {
		t.Fatalf("loadReusableMetadata failed: %v", err)
	}
	loadedTor := imp.Torrent
	hashes := imp.HashResults

	if loadedTor == nil {
		t.Fatal("Expected torrent to be loaded")
	}

	res, ok := hashes[9999]
	if !ok {
		t.Errorf("Expected size 9999 to be imported from torrent")
	}
	if len(res.SHA1PieceHashes) != 1 {
		t.Errorf("Expected 1 piece hash, got %d", len(res.SHA1PieceHashes))
	}
	if res.SHA1PieceHashes[0] != hex.EncodeToString([]byte(dummySHA1)) {
		t.Errorf("Wrong piece hash imported from torrent")
	}
	// Note: We don't extract SHA-1 pieces from torrents anymore
}

func TestFilesFromReusableMetadata(t *testing.T) {
	files, isDir, err := filesFromReusableMetadata("/tmp/new-name", nil, nil, &Torrent{
		Info: TorrentInfo{
			Length: 123,
		},
	})
	if err != nil {
		t.Fatalf("filesFromReusableMetadata failed: %v", err)
	}
	if isDir {
		t.Fatal("single-file metadata was identified as a directory")
	}
	if len(files) != 1 || files[0].RelPath != "new-name" || files[0].Size != 123 {
		t.Fatalf("unexpected single-file metadata: %+v", files)
	}

	files, isDir, err = filesFromReusableMetadata("/tmp/new-folder/", nil, nil, &Torrent{
		Info: TorrentInfo{
			Files: []TorrentFileInfo{
				{Length: 10, Path: []string{"nested", "one"}},
				{Length: 20, Path: []string{"two"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("filesFromReusableMetadata failed: %v", err)
	}
	if !isDir {
		t.Fatal("multi-file metadata was not identified as a directory")
	}
	if len(files) != 2 || files[0].RelPath != filepath.Join("nested", "one") || files[1].RelPath != "two" {
		t.Fatalf("unexpected multi-file metadata: %+v", files)
	}

	files, isDir, err = filesFromReusableMetadata("/tmp/new-folder/", map[int64]FileHashResult{
		10: {RelPath: "old-folder/nested/one", Size: 10},
		20: {RelPath: "old-folder/two", Size: 20},
	}, nil, nil)
	if err != nil {
		t.Fatalf("filesFromReusableMetadata failed: %v", err)
	}
	if !isDir || len(files) != 2 || files[0].RelPath != filepath.Join("nested", "one") || files[1].RelPath != "two" {
		t.Fatalf("unexpected metalink-only metadata: %+v", files)
	}

	// Same-size files that collide in the size-keyed hash map must still be
	// listed when the metalink's own file list is available.
	metaFiles := []FileInfo{
		{RelPath: "old-folder/x1.bin", Size: 7},
		{RelPath: "old-folder/x2.bin", Size: 7},
		{RelPath: "old-folder/u.bin", Size: 6},
	}
	files, isDir, err = filesFromReusableMetadata("/tmp/new-folder/", map[int64]FileHashResult{
		6: {RelPath: "old-folder/u.bin", Size: 6},
	}, metaFiles, nil)
	if err != nil {
		t.Fatalf("filesFromReusableMetadata failed: %v", err)
	}
	if !isDir || len(files) != 3 || files[0].RelPath != "x1.bin" || files[1].RelPath != "x2.bin" || files[2].RelPath != "u.bin" {
		t.Fatalf("unexpected colliding metalink metadata: %+v", files)
	}

	// The package prefix is stripped from the metadata paths even when the
	// metadata file itself has been renamed.
	renamed := []FileInfo{
		{RelPath: "renamed-pkg/sub/one.txt", Size: 10},
		{RelPath: "renamed-pkg/two.txt", Size: 20},
	}
	files, isDir, err = filesFromReusableMetadata("/tmp/new-folder/", map[int64]FileHashResult{
		10: {RelPath: "renamed-pkg/sub/one.txt", Size: 10},
		20: {RelPath: "renamed-pkg/two.txt", Size: 20},
	}, renamed, nil)
	if err != nil {
		t.Fatalf("filesFromReusableMetadata failed: %v", err)
	}
	if !isDir || len(files) != 2 || files[0].RelPath != filepath.Join("sub", "one.txt") || files[1].RelPath != "two.txt" {
		t.Fatalf("unexpected prefix handling: %+v", files)
	}
}

func TestFilesFromReusableMetadataSingleFileDir(t *testing.T) {
	// A metalink for a directory that contains exactly one file records the
	// nested path below the package root; it must not be flattened.
	metaFiles := []FileInfo{
		{RelPath: "pkg/sub/only.txt", Size: 10},
	}
	files, isDir, err := filesFromReusableMetadata("/tmp/new-folder", map[int64]FileHashResult{
		10: {RelPath: "pkg/sub/only.txt", Size: 10},
	}, metaFiles, nil)
	if err != nil {
		t.Fatalf("filesFromReusableMetadata failed: %v", err)
	}
	if !isDir {
		t.Fatal("single-file directory was identified as a single file")
	}
	if len(files) != 1 || files[0].RelPath != filepath.Join("sub", "only.txt") {
		t.Fatalf("unexpected single-file directory metadata: %+v", files)
	}
}

func TestLoadReusableMetadataAllCollisions(t *testing.T) {
	// Every file sharing a size must still resolve by relative path instead of
	// failing to load, even though the size-keyed hash map ends up empty.
	tmpFile, err := os.CreateTemp("", "import-*.meta4")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := `<?xml version="1.0" encoding="UTF-8"?>
<metalink xmlns="urn:ietf:params:xml:ns:metalink">
  <file name="pkg/a.bin">
    <size>555</size>
    <hash type="sha-256">aaaa</hash>
  </file>
  <file name="pkg/b.bin">
    <size>555</size>
    <hash type="sha-256">bbbb</hash>
  </file>
</metalink>`
	if _, err := tmpFile.Write([]byte(content)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	imp, err := loadReusableMetadata(tmpFile.Name())
	if err != nil {
		t.Fatalf("loadReusableMetadata failed: %v", err)
	}
	if len(imp.HashResults) != 0 {
		t.Errorf("expected empty size-keyed map, got %d", len(imp.HashResults))
	}
	if len(imp.MetaByRel) != 2 || imp.MetaByRel[filepath.FromSlash("a.bin")].FileSHA256 != "aaaa" || imp.MetaByRel[filepath.FromSlash("b.bin")].FileSHA256 != "bbbb" {
		t.Errorf("colliding files not resolvable by path: %+v", imp.MetaByRel)
	}
}

func TestLoadReusableMetadataPieceLength(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "import-*.meta4")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := `<?xml version="1.0" encoding="UTF-8"?>
<metalink xmlns="urn:ietf:params:xml:ns:metalink">
  <file name="a.bin">
    <size>1024</size>
    <pieces type="sha-256" length="1024">
      <hash>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</hash>
    </pieces>
  </file>
</metalink>`
	if _, err := tmpFile.Write([]byte(content)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	imp, err := loadReusableMetadata(tmpFile.Name())
	if err != nil {
		t.Fatalf("loadReusableMetadata failed: %v", err)
	}
	if imp.MetaPieceLength != 1024 {
		t.Errorf("expected metalink piece length 1024, got %d", imp.MetaPieceLength)
	}
}

func TestTorrentValidity(t *testing.T) {
	// Mock a Torrent
	tor := Torrent{
		Announce: "http://tracker.com/announce",
		Info: TorrentInfo{
			PieceLength: 1024,
			Pieces:      string(make([]byte, 20)),
			Name:        "test-torrent",
			Length:      1024,
		},
	}

	var buf bytes.Buffer
	if err := bencode.Marshal(&buf, tor); err != nil {
		t.Fatalf("bencode marshal failed: %v", err)
	}

	// Round-trip test
	var r Torrent
	if err := bencode.Unmarshal(&buf, &r); err != nil {
		t.Fatalf("bencode unmarshal failed: %v", err)
	}

	if r.Announce != tor.Announce {
		t.Errorf("Torrent announce mismatch: %s", r.Announce)
	}
	if r.Info.Name != tor.Info.Name {
		t.Errorf("Torrent info name mismatch: %s", r.Info.Name)
	}
	if len(r.Info.Pieces) != 20 {
		t.Errorf("Torrent pieces corrupted: len %d", len(r.Info.Pieces))
	}
}

func TestFullWorkflow(t *testing.T) {
	// Create a temp file to package
	tmpDir, err := os.MkdirTemp("", "mkmetalink-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filePath := filepath.Join(tmpDir, "testfile.dat")
	data := []byte("The quick brown fox jumps over the lazy dog.")
	if err := os.WriteFile(filePath, data, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// We'll test piece calculation and hashing manually since main() calls log.Fatalf on error
	// and is hard to isolate.
	totalSize := int64(len(data))
	pieceSize := int64(1024 * 1024)

	mh := NewMultiHasher(pieceSize, pieceSize)
	mh.StartFile("testfile.dat")
	mh.Write(data)
	mh.EndFile()
	mh.Finalize()

	results := mh.GetResults()
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Validate results
	r := results[0]
	if r.Size != totalSize {
		t.Errorf("Expected size %d, got %d", totalSize, r.Size)
	}

	// Verify we can create the structs from these results (mimicking main loop)
	meta := Metalink{
		XMLNs:   "urn:ietf:params:xml:ns:metalink",
		Version: "4.0",
	}
	mf := MetalinkFile{
		Name: "testfile.dat",
		Size: r.Size,
		Hash: MetaHash{
			Type:  "sha-256",
			Value: r.FileSHA256,
		},
		Pieces: MetaPieces{
			Type:   "sha-256",
			Length: pieceSize,
		},
	}
	meta.Files = append(meta.Files, mf)

	tor := Torrent{
		Announce: "http://tracker.com",
		Info: TorrentInfo{
			PieceLength: pieceSize,
			Pieces:      string(mh.GetTorrentPieces()),
			Name:        "test",
			Length:      totalSize,
		},
	}

	// Ensure no errors when serializing actual data
	var xmlBuf bytes.Buffer
	if err := xml.NewEncoder(&xmlBuf).Encode(meta); err != nil {
		t.Errorf("Final XML encode failed: %v", err)
	}

	var torBuf bytes.Buffer
	if err := bencode.Marshal(&torBuf, tor); err != nil {
		t.Fatalf("Final Torrent marshal failed: %v", err)
	}
}

func TestMultiHasherDistinctPieceSizes(t *testing.T) {
	// The metalink (SHA-256, resets per file) and torrent (SHA-1, crosses file
	// boundaries) streams must be able to use different piece sizes, matching
	// imported metadata that disagree on their piece length.
	mh := NewMultiHasher(4, 5)
	mh.StartFile("f.bin")
	mh.Write([]byte("abcdefghij"))
	mh.EndFile()
	mh.Finalize()

	res := mh.GetResults()[0]
	if len(res.SHA256PieceHashes) != 3 {
		t.Errorf("metalink (SHA-256) pieces = %d; want 3 (size 4)", len(res.SHA256PieceHashes))
	}
	if want := 2 * 20; len(mh.GetTorrentPieces()) != want {
		t.Errorf("torrent (SHA-1) pieces byte length = %d; want %d (size 5)", len(mh.GetTorrentPieces()), want)
	}
}

func TestCanReuseTorrentPieces(t *testing.T) {
	tor := &Torrent{Info: TorrentInfo{
		PieceLength: 1024,
		Files: []TorrentFileInfo{
			{Length: 4, Path: []string{"a"}},
			{Length: 6, Path: []string{"b"}},
		},
	}}
	files := []FileInfo{{RelPath: "a", Size: 4}, {RelPath: "b", Size: 6}}

	if !canReuseTorrentPieces(files, tor, 1024, false) {
		t.Error("matching multi-file layout should allow torrent piece reuse")
	}
	if canReuseTorrentPieces(files, nil, 1024, true) {
		t.Error("nil torrent should never allow reuse")
	}
	if canReuseTorrentPieces(files, tor, 2048, false) {
		t.Error("torrent piece length must match the emitted piece length")
	}
	// A different file order must not count as a match.
	reorder := []FileInfo{{RelPath: "b", Size: 6}, {RelPath: "a", Size: 4}}
	if canReuseTorrentPieces(reorder, tor, 1024, false) {
		t.Error("reordered files must not allow torrent piece reuse")
	}

	// --ignore-size trusts the override even when the sizes no longer match:
	// files are never dropped, the whole piece blob is reused regardless.
	drifted := []FileInfo{{RelPath: "a", Size: 99}, {RelPath: "b", Size: 3}}
	if !canReuseTorrentPieces(drifted, tor, 1024, true) {
		t.Error("--ignore-size should allow torrent piece reuse despite size drift")
	}
	if canReuseTorrentPieces(drifted, tor, 1024, false) {
		t.Error("without --ignore-size a size drift must block torrent piece reuse")
	}

	// Single-file torrent: the recorded length must match.
	single := &Torrent{Info: TorrentInfo{PieceLength: 1024, Length: 100}}
	if !canReuseTorrentPieces([]FileInfo{{RelPath: "x", Size: 100}}, single, 1024, false) {
		t.Error("matching single-file length should allow torrent piece reuse")
	}
	if canReuseTorrentPieces([]FileInfo{{RelPath: "x", Size: 200}}, single, 1024, false) {
		t.Error("differing single-file length should block torrent piece reuse")
	}
}

func TestResolveReuse(t *testing.T) {
	hashes := map[int64]FileHashResult{
		10: {RelPath: "x.bin", Size: 10, FileSHA256: "aaa", SHA256PieceHashes: []string{"p1", "p2"}},
	}
	byRel := map[string]FileHashResult{
		"x.bin": {RelPath: "x.bin", Size: 10, FileSHA256: "bbb"},
		"other": {RelPath: "other", Size: 99, FileSHA256: "ccc"},
	}

	// Size-keyed index is authoritative by default.
	r, ok := resolveReuse(FileInfo{RelPath: "x.bin", Size: 10}, hashes, byRel, true, false, 1024)
	if !ok || r.FileSHA256 != "aaa" {
		t.Errorf("size-keyed lookup failed: %+v ok=%v", r, ok)
	}

	// Path-indexed fallback resolves same-size collisions absent from the
	// size-keyed index.
	r, ok = resolveReuse(FileInfo{RelPath: "other", Size: 99}, hashes, byRel, true, false, 1024)
	if !ok || r.FileSHA256 != "ccc" {
		t.Errorf("path fallback failed: %+v ok=%v", r, ok)
	}

	// A path match with a different size is rejected when the file exists.
	if r, ok = resolveReuse(FileInfo{RelPath: "x.bin", Size: 11}, hashes, byRel, true, false, 1024); ok {
		t.Errorf("path fallback with differing size and existing path should be rejected: %+v", r)
	}

	// --ignore-size prefers the relative-path index and ignores sizes.
	r, ok = resolveReuse(FileInfo{RelPath: "x.bin", Size: 11}, hashes, byRel, true, true, 1024)
	if !ok || r.FileSHA256 != "bbb" {
		t.Errorf("--ignore-size path lookup failed: %+v ok=%v", r, ok)
	}

	// SHA-256 piece hashes are kept when the metalink piece length is known.
	if r, ok = resolveReuse(FileInfo{RelPath: "x.bin", Size: 10}, hashes, nil, true, false, 1024); !ok || len(r.SHA256PieceHashes) != 2 {
		t.Errorf("known piece length should keep piece hashes: %+v ok=%v", r, ok)
	}

	// ...and stripped when the metalink piece length is unknown, so the file
	// gets rehashed instead of emitting <pieces> with mismatched hashes.
	if r, ok = resolveReuse(FileInfo{RelPath: "x.bin", Size: 10}, hashes, nil, true, false, 0); !ok || len(r.SHA256PieceHashes) != 0 {
		t.Errorf("unknown piece length should strip piece hashes: %+v ok=%v", r, ok)
	}

	// --ignore-size must not bypass that strip.
	if r, ok = resolveReuse(FileInfo{RelPath: "x.bin", Size: 10}, hashes, nil, true, true, 0); !ok || len(r.SHA256PieceHashes) != 0 {
		t.Errorf("--ignore-size must not bypass the piece-length guard: %+v ok=%v", r, ok)
	}
}

func TestCanSkipReuse(t *testing.T) {
	reused := FileHashResult{FileSHA256: "x", SHA256PieceHashes: []string{"p"}}
	if !canSkipReuse(FileInfo{Size: 12}, reused, true, true, true) {
		t.Error("full reuse should allow skipping")
	}
	// A file hash without valid pieces cannot feed the metalink.
	if canSkipReuse(FileInfo{Size: 12}, FileHashResult{FileSHA256: "x"}, true, true, true) {
		t.Error("file without valid pieces must be rehashed when the metalink needs it")
	}
	// When no torrent output is needed, torrent reusability is irrelevant.
	if !canSkipReuse(FileInfo{Size: 12}, reused, true, false, false) {
		t.Error("skip should not depend on torrent reuse when no torrent output is emitted")
	}
	// An empty file has a valid file-level SHA-256 with no pieces at all.
	if !canSkipReuse(FileInfo{Size: 0}, FileHashResult{FileSHA256: "x"}, true, true, true) {
		t.Error("empty file with its file hash should be skippable")
	}
}

func TestImportedHashCount(t *testing.T) {
	imp := &ReusableMetadata{
		HashResults: map[int64]FileHashResult{
			10: {RelPath: "a.bin", Size: 10},
			20: {RelPath: "b.bin", Size: 20},
		},
		MetaByRel: map[string]FileHashResult{
			"a.bin": {RelPath: "a.bin", Size: 10},
			"x.bin": {RelPath: "x.bin", Size: 7},
			"y.bin": {RelPath: "y.bin", Size: 7},
		},
	}
	if got := importedHashCount(imp); got != 4 {
		t.Errorf("importedHashCount = %d; want 4 (a, b, x, y)", got)
	}

	// All files colliding by size: the size-keyed map is empty but the
	// path-indexed entries are still distinct imports.
	collide := &ReusableMetadata{
		HashResults: map[int64]FileHashResult{},
		MetaByRel: map[string]FileHashResult{
			"a.bin": {RelPath: "a.bin", Size: 555},
			"b.bin": {RelPath: "b.bin", Size: 555},
		},
	}
	if got := importedHashCount(collide); got != 2 {
		t.Errorf("importedHashCount (all collisions) = %d; want 2", got)
	}

	// A metalink + torrent pair for the same file is one import even though the
	// merged size-keyed record may carry the torrent's path while the
	// path-indexed record carries the metalink's package-qualified path.
	merged := &ReusableMetadata{
		HashResults: map[int64]FileHashResult{
			10: {RelPath: "data.bin", Size: 10, FileSHA256: "m", SHA1PieceHashes: []string{"t"}},
		},
		MetaByRel: map[string]FileHashResult{
			"data.bin": {RelPath: "pkg/data.bin", Size: 10, FileSHA256: "m"},
		},
	}
	if got := importedHashCount(merged); got != 1 {
		t.Errorf("importedHashCount (merged metalink+torrent) = %d; want 1", got)
	}
}
