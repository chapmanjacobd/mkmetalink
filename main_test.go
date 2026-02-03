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
	mh := NewMultiHasher(pieceSize)

	// File 1: "abcd" (exactly 1 piece)
	mh.StartFile("file1.txt")
	mh.Write([]byte("abcd"))
	res1 := mh.EndFile()

	if res1.Size != 4 {
		t.Errorf("res1 size = %d; want 4", res1.Size)
	}
	if len(res1.PieceHashes) != 1 {
		t.Errorf("res1 piece count = %d; want 1", len(res1.PieceHashes))
	}

	// File 2: "efghi" (1 full piece + 1 partial piece)
	mh.StartFile("file2.txt")
	mh.Write([]byte("efgh"))
	mh.Write([]byte("i"))
	res2 := mh.EndFile()

	if res2.Size != 5 {
		t.Errorf("res2 size = %d; want 5", res2.Size)
	}
	if len(res2.PieceHashes) != 2 {
		t.Errorf("res2 piece count = %d; want 2", len(res2.PieceHashes))
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
					Length: 1024,
					Type:   "sha-256",
					Hashes: []MetaPieceHash{{Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
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

	hashes, _, err := loadReusableMetadata(tmpFile.Name())
	if err != nil {
		t.Fatalf("loadReusableMetadata failed: %v", err)
	}

	if len(hashes) != 1 {
		t.Errorf("Expected 1 unique hash (excluding duplicates), got %d", len(hashes))
	}

	res, ok := hashes[1234]
	if !ok {
		t.Errorf("Expected size 1234 to be present")
	}
	if res.FileSHA256 != "916f0027c57591d1e1388d40733544a631bf2a7d88598c099309605470d0473a" {
		t.Errorf("Wrong hash imported")
	}
	if len(res.PieceHashes) != 1 || res.PieceHashes[0] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
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
	hashes, loadedTor, err := loadReusableMetadata(filepath.Join(tmpDir, "test"))
	if err != nil {
		t.Fatalf("loadReusableMetadata failed: %v", err)
	}

	if loadedTor == nil {
		t.Fatal("Expected torrent to be loaded")
	}

	res, ok := hashes[9999]
	if !ok {
		t.Errorf("Expected size 9999 to be imported from torrent")
	}
	if res.PieceHashType != "sha-1" {
		t.Errorf("Expected piece hash type sha-1, got %s", res.PieceHashType)
	}
	if len(res.PieceHashes) != 1 {
		t.Errorf("Expected 1 piece hash, got %d", len(res.PieceHashes))
	}
	if res.PieceHashes[0] != hex.EncodeToString([]byte(dummySHA1)) {
		t.Errorf("Wrong piece hash imported from torrent")
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

	mh := NewMultiHasher(pieceSize)
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
			Length: pieceSize,
			Type:   "sha-256",
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
		t.Errorf("Final Torrent marshal failed: %v", err)
	}
}
