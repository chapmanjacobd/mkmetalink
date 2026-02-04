package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"hash"
	"io"
	"log"
	"math"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/jackpal/bencode-go"
)

const (
	P_MIN       = 256 * 1024
	P_CAP       = 4 * 1024 * 1024
	P_MAX       = 64 * 1024 * 1024
	N_THRESHOLD = 7500
	CHUNK_SIZE  = 32 * 1024 * 1024
)

func calculatePieceSize(total int64) int64 {
	if total <= 0 {
		return P_MIN
	}

	logExp := math.Floor(math.Log2(float64(total)) - 10)
	baseLog := int64(math.Max(float64(P_MIN), math.Pow(2, logExp)))
	current := baseLog
	if current > P_CAP {
		current = P_CAP
	}

	currentPieces := float64(total) / float64(current)
	if currentPieces > N_THRESHOLD {
		target := float64(total) / N_THRESHOLD
		stepped := int64(math.Pow(2, math.Ceil(math.Log2(target))))
		if stepped < P_CAP {
			stepped = P_CAP
		}
		if stepped > P_MAX {
			stepped = P_MAX
		}
		current = stepped
	}

	if current < P_MIN {
		current = P_MIN
	}
	return current
}

func formatBytes(b int64) string {
	if b == 0 {
		return "0 B"
	}

	size := float64(b)
	base := 1024.0
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}

	i := math.Floor(math.Log(size) / math.Log(base))

	// Bound the index
	if i >= float64(len(units)) {
		i = float64(len(units) - 1)
	}

	return fmt.Sprintf("%.1f %s", size/math.Pow(base, i), units[int(i)])
}

// ---------- Metalink (RFC5854) XML structs ----------

type Metalink struct {
	XMLName   xml.Name       `xml:"metalink"`
	XMLNs     string         `xml:"xmlns,attr"`
	Version   string         `xml:"version,attr,omitempty"`
	Metaurls  []MetaURL      `xml:"metaurl,omitempty"`
	Files     []MetalinkFile `xml:"file"`
	Signature *MetaSignature `xml:"signature,omitempty"`
}

type MetaURL struct {
	Priority  int    `xml:"priority,attr,omitempty"`
	MediaType string `xml:"mediatype,attr,omitempty"`
	Name      string `xml:"name,attr,omitempty"`
	Value     string `xml:",chardata"`
}

type MetalinkFile struct {
	Name     string        `xml:"name,attr"`
	Size     int64         `xml:"size"`
	Hash     MetaHash      `xml:"hash"`
	Pieces   MetaPieces    `xml:"pieces"`
	URLs     []MetalinkURL `xml:"url,omitempty"`
	Metaurls []MetaURL     `xml:"metaurl,omitempty"`
}

type MetaHash struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type MetaPieces struct {
	Type   string          `xml:"type,attr"`
	Length int64           `xml:"length,attr"`
	Hashes []MetaPieceHash `xml:"hash"`
}

type MetaPieceHash struct {
	Type  string `xml:"type,attr,omitempty"`
	Value string `xml:",chardata"`
}

type MetalinkURL struct {
	Priority int    `xml:"priority,attr,omitempty"`
	Value    string `xml:",chardata"`
}

type MetaSignature struct {
	Mediatype string `xml:"mediatype,attr"`
	Value     string `xml:",chardata"`
}

// ---------- Torrent structures (bencode) ----------

type Torrent struct {
	Announce     string      `bencode:"announce"`
	AnnounceList [][]string  `bencode:"announce-list,omitempty"`
	URLList      []string    `bencode:"url-list,omitempty"`
	Info         TorrentInfo `bencode:"info"`
}

type TorrentInfo struct {
	PieceLength int64             `bencode:"piece length"`
	Pieces      string            `bencode:"pieces"`
	Name        string            `bencode:"name"`
	Length      int64             `bencode:"length,omitempty"`
	Files       []TorrentFileInfo `bencode:"files,omitempty"`
	Private     int64             `bencode:"private,omitempty"`
	Source      string            `bencode:"source,omitempty"`
}

type TorrentFileInfo struct {
	Length int64    `bencode:"length"`
	Path   []string `bencode:"path"`
}

var CLI struct {
	Sign    string   `help:"If set, pass this GPG --local-user (key id) to sign" optional:"" aliases:"pgp,gpg"`
	Tracker string   `help:"Tracker URL for generated torrent's announce (default privtracker)" default:"https://privtracker.com/metalink/announce"`
	OutDir  string   `help:"Optional output directory for generated files. Default: input file's parent directory or input directory" short:"o" optional:""`
	Modify  string   `help:"Reuse hashes from an existing metalink/torrent (matches by file size)" type:"path" optional:""`
	Mirrors []string `name:"mirrors" short:"m" help:"HTTPS mirrors (if directory: base URLs)"`

	Path string `arg:"" name:"path" help:"File or directory to package" type:"path"`
}

type FileInfo struct {
	RelPath string
	Size    int64
}

type FileHashResult struct {
	RelPath           string
	Size              int64
	FileSHA256        string   // hex encoded
	SHA256PieceHashes []string // for Metalink
	SHA1PieceHashes   []string // for Torrent
	Err               error
}

type MultiHasher struct {
	pieceSize int64

	// SHA-1 for torrent (crosses file boundaries)
	torrentPieceCounter int64
	torrentPieceSHA1    hash.Hash
	torrentPieces       *bytes.Buffer

	// SHA-256 for current file
	fileSHA256 hash.Hash

	// SHA-256 for per-file pieces (resets at file boundaries)
	filePieceSHA256      hash.Hash
	filePieceBuffer      int64
	currentFilePieceList []string
	currentFileByteCount int64
	currentFileRelPath   string

	results []FileHashResult
}

func NewMultiHasher(pieceSize int64) *MultiHasher {
	return &MultiHasher{
		pieceSize:           pieceSize,
		torrentPieceCounter: 0,
		torrentPieceSHA1:    sha1.New(),
		torrentPieces:       new(bytes.Buffer),
		fileSHA256:          sha256.New(),
		filePieceSHA256:     sha256.New(),
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (mh *MultiHasher) SkipFile(relPath string, size int64, sha256 string, sha256Pieces []string, sha1Pieces []string) {
	mh.results = append(mh.results, FileHashResult{
		RelPath:           relPath,
		Size:              size,
		FileSHA256:        sha256,
		SHA256PieceHashes: sha256Pieces,
		SHA1PieceHashes:   sha1Pieces,
	})
}

func (mh *MultiHasher) StartFile(relPath string) {
	mh.currentFileRelPath = relPath
	mh.fileSHA256.Reset()
	mh.filePieceSHA256.Reset()
	mh.filePieceBuffer = 0
	mh.currentFilePieceList = nil
	mh.currentFileByteCount = 0
}

// Write processes a chunk of data
func (mh *MultiHasher) Write(data []byte) error {
	// Update file-level SHA-256
	mh.fileSHA256.Write(data)
	mh.currentFileByteCount += int64(len(data))

	offset := 0
	for offset < len(data) {
		// Process file-piece SHA-256 (resets at file boundaries)
		spaceLeftFile := mh.pieceSize - mh.filePieceBuffer
		toWriteFile := int64(len(data) - offset)
		if toWriteFile > spaceLeftFile {
			toWriteFile = spaceLeftFile
		}

		chunk := data[offset : offset+int(toWriteFile)]
		mh.filePieceSHA256.Write(chunk)
		mh.filePieceBuffer += toWriteFile

		// Check if file piece is complete
		if mh.filePieceBuffer == mh.pieceSize {
			h := mh.filePieceSHA256.Sum(nil)
			mh.currentFilePieceList = append(mh.currentFilePieceList, hex.EncodeToString(h))
			mh.filePieceSHA256.Reset()
			mh.filePieceBuffer = 0
		}

		offset += int(toWriteFile)
	}

	// Process torrent pieces (crosses file boundaries)
	offset = 0
	for offset < len(data) {
		spaceLeftTorrent := mh.pieceSize - mh.torrentPieceCounter
		toWriteTorrent := int64(len(data) - offset)
		if toWriteTorrent > spaceLeftTorrent {
			toWriteTorrent = spaceLeftTorrent
		}

		chunk := data[offset : offset+int(toWriteTorrent)]
		mh.torrentPieceSHA1.Write(chunk)
		mh.torrentPieceCounter += toWriteTorrent
		offset += int(toWriteTorrent)

		// Check if torrent piece is complete
		if mh.torrentPieceCounter == mh.pieceSize {
			sum := mh.torrentPieceSHA1.Sum(nil)
			mh.torrentPieces.Write(sum)
			mh.torrentPieceSHA1.Reset()
			mh.torrentPieceCounter = 0
		}
	}

	return nil
}

func (mh *MultiHasher) EndFile() FileHashResult {
	// Finalize file-level SHA-256
	fileSHA256Hex := hex.EncodeToString(mh.fileSHA256.Sum(nil))

	// Finalize last partial file piece if any
	if mh.filePieceBuffer > 0 {
		h := mh.filePieceSHA256.Sum(nil)
		mh.currentFilePieceList = append(mh.currentFilePieceList, hex.EncodeToString(h))
	}

	result := FileHashResult{
		RelPath:           mh.currentFileRelPath,
		Size:              mh.currentFileByteCount,
		FileSHA256:        fileSHA256Hex,
		SHA256PieceHashes: mh.currentFilePieceList,
		Err:               nil,
	}

	mh.results = append(mh.results, result)
	return result
}

func (mh *MultiHasher) Finalize() {
	// Finalize last torrent piece if partial
	if mh.torrentPieceCounter > 0 {
		sum := mh.torrentPieceSHA1.Sum(nil)
		mh.torrentPieces.Write(sum)
	}
}

func (mh *MultiHasher) GetTorrentPieces() []byte {
	return mh.torrentPieces.Bytes()
}

func (mh *MultiHasher) GetResults() []FileHashResult {
	return mh.results
}

func (mh *MultiHasher) SetTorrentPieces(pieces []byte) {
	mh.torrentPieces.Reset()
	mh.torrentPieces.Write(pieces)
}

func loadReusableMetadata(path string) (map[int64]FileHashResult, *Torrent, bool, bool, error) {
	base := strings.TrimSuffix(path, ".meta4")
	base = strings.TrimSuffix(base, ".torrent")

	res := make(map[int64]FileHashResult)
	collisions := make(map[int64]bool)

	// Helper to add results with collision detection
	addResult := func(size int64, r FileHashResult) {
		if collisions[size] {
			return
		}
		if existing, ok := res[size]; ok {
			// If it's the exact same hash/pieces, it's just a duplicate entry, ignore.
			// But if any hash differs, it's a collision.
			collision := false
			if existing.FileSHA256 != "" && r.FileSHA256 != "" && existing.FileSHA256 != r.FileSHA256 {
				collision = true
			}
			// If they have different pieces of the SAME type, collision.
			if len(existing.SHA256PieceHashes) > 0 && len(r.SHA256PieceHashes) > 0 && !equalSlices(existing.SHA256PieceHashes, r.SHA256PieceHashes) {
				collision = true
			}
			if len(existing.SHA1PieceHashes) > 0 && len(r.SHA1PieceHashes) > 0 && !equalSlices(existing.SHA1PieceHashes, r.SHA1PieceHashes) {
				collision = true
			}

			if collision {
				delete(res, size)
				collisions[size] = true
				return
			}

			// Merge them
			if r.FileSHA256 == "" {
				r.FileSHA256 = existing.FileSHA256
			}
			if len(r.SHA256PieceHashes) == 0 {
				r.SHA256PieceHashes = existing.SHA256PieceHashes
			}
			if len(r.SHA1PieceHashes) == 0 {
				r.SHA1PieceHashes = existing.SHA1PieceHashes
			}
		}
		res[size] = r
	}

	metaFound := false
	metaPath := base + ".meta4"
	if metaData, err := os.ReadFile(metaPath); err == nil {
		metaFound = true
		var meta Metalink
		if err := xml.Unmarshal(metaData, &meta); err == nil {
			for _, f := range meta.Files {
				var fileSHA256 string
				if strings.ToLower(f.Hash.Type) == "sha-256" {
					fileSHA256 = f.Hash.Value
				}
				var sha256Pieces []string
				if strings.ToLower(f.Pieces.Type) == "sha-256" {
					for _, ph := range f.Pieces.Hashes {
						sha256Pieces = append(sha256Pieces, ph.Value)
					}
				}
				if fileSHA256 != "" || len(sha256Pieces) > 0 {
					addResult(f.Size, FileHashResult{
						RelPath:           f.Name,
						Size:              f.Size,
						FileSHA256:        fileSHA256,
						SHA256PieceHashes: sha256Pieces,
					})
				}
			}
		}
	}

	// 2. Try loading Torrent
	var torFound bool
	var tor *Torrent
	torPath := base + ".torrent"
	if torData, err := os.ReadFile(torPath); err == nil {
		torFound = true
		var t Torrent
		if err := bencode.Unmarshal(bytes.NewReader(torData), &t); err == nil {
			tor = &t
			pieces := []byte(t.Info.Pieces)
			if len(pieces)%20 == 0 {
				numPieces := len(pieces) / 20
				if len(t.Info.Files) > 0 {
					var currentOffset int64
					for _, f := range t.Info.Files {
						startPiece := currentOffset / t.Info.PieceLength
						endPiece := (currentOffset + f.Length - 1) / t.Info.PieceLength

						var phs []string
						for p := startPiece; p <= endPiece && p < int64(numPieces); p++ {
							phs = append(phs, hex.EncodeToString(pieces[p*20:(p+1)*20]))
						}

						r := FileHashResult{
							RelPath:         strings.Join(f.Path, "/"),
							Size:            f.Length,
							SHA1PieceHashes: phs,
						}
						addResult(f.Length, r)
						currentOffset += f.Length
					}
				} else if t.Info.Length > 0 {
					var phs []string
					for p := 0; p < numPieces; p++ {
						phs = append(phs, hex.EncodeToString(pieces[p*20:(p+1)*20]))
					}
					r := FileHashResult{
						RelPath:         t.Info.Name,
						Size:            t.Info.Length,
						SHA1PieceHashes: phs,
					}
					addResult(t.Info.Length, r)
				}
			}
		}
	}

	if len(res) == 0 && tor == nil {
		return nil, nil, false, false, fmt.Errorf("no reusable metadata found at %s(.meta4/.torrent)", base)
	}

	return res, tor, metaFound, torFound, nil
}

func main() {
	ctx := kong.Parse(&CLI)
	_ = ctx

	info, err := os.Stat(CLI.Path)
	if err != nil {
		log.Fatalf("stat %s: %v", CLI.Path, err)
	}

	var files []FileInfo
	var total int64

	if info.IsDir() {
		err = filepath.WalkDir(CLI.Path, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.Type().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(CLI.Path, path)
			if err != nil {
				return err
			}
			fi, err := d.Info()
			if err != nil {
				return err
			}
			files = append(files, FileInfo{RelPath: rel, Size: fi.Size()})
			total += fi.Size()
			return nil
		})
		if err != nil {
			log.Fatalf("walk: %v", err)
		}
	} else {
		files = []FileInfo{{RelPath: filepath.Base(CLI.Path), Size: info.Size()}}
		total = info.Size()
	}

	if len(files) == 0 {
		log.Fatalf("no files found under %s", CLI.Path)
	}

	pieceSize := calculatePieceSize(total)

	var importedHashes map[int64]FileHashResult
	var importedTorrent *Torrent
	var metaFound, torFound bool

	if CLI.Modify != "" {
		var err error
		importedHashes, importedTorrent, metaFound, torFound, err = loadReusableMetadata(CLI.Modify)
		if err != nil {
			log.Printf("Warning: failed to load reusable metadata: %v", err)
		} else {
			source := ""
			if metaFound && torFound {
				source = "Metalink and Torrent"
			} else if metaFound {
				source = "Metalink"
			} else if torFound {
				source = "Torrent"
			}
			fmt.Printf("Imported %d unique hashes from %s (%s)\n", len(importedHashes), CLI.Modify, source)

			if importedTorrent != nil {
				// Adopt piece size from imported torrent to facilitate reuse/consistency
				if pieceSize != importedTorrent.Info.PieceLength {
					fmt.Printf("Note: Adoption of imported torrent piece size %s (was %s)\n", formatBytes(importedTorrent.Info.PieceLength), formatBytes(pieceSize))
					pieceSize = importedTorrent.Info.PieceLength
				}
			}
		}
	}

	fmt.Printf("Total size: %s, piece size: %s, %d files\n", formatBytes(total), formatBytes(pieceSize), len(files))

	canReuseTorrent := false
	if importedTorrent != nil && importedTorrent.Info.PieceLength == pieceSize {
		// Check if file sequence matches for torrent piece reuse
		if len(files) == 1 && importedTorrent.Info.Length == files[0].Size {
			canReuseTorrent = true
		} else if len(files) == len(importedTorrent.Info.Files) {
			match := true
			for i, fi := range files {
				if fi.Size != importedTorrent.Info.Files[i].Length {
					match = false
					break
				}
			}
			canReuseTorrent = match
		}
	}

	// Single-pass hashing: both torrent (SHA-1) and per-file (SHA-256)
	mh := NewMultiHasher(pieceSize)

	startTime := time.Now()
	var totalBytesProcessed int64

	// Reuse buffer across all files
	buf := make([]byte, CHUNK_SIZE)

	for _, fi := range files {
		full := CLI.Path
		if info.IsDir() {
			full = filepath.Join(CLI.Path, fi.RelPath)
		}

		mh.StartFile(fi.RelPath)

		if imported, ok := importedHashes[fi.Size]; ok {
			needSHA256 := (CLI.Modify == "" || metaFound)
			hasSHA256 := (imported.FileSHA256 != "" && len(imported.SHA256PieceHashes) > 0)
			needSHA1 := (CLI.Modify == "" || torFound)
			// We can only skip if:
			// 1. We don't need SHA256 OR we already have it from import
			// 2. We don't need SHA1 OR we can reuse the BitTorrent pieces
			if (!needSHA256 || hasSHA256) && (!needSHA1 || canReuseTorrent) {
				status := "hashes"
				if canReuseTorrent {
					status = "all hashes"
				}
				fmt.Printf("  %.1f%%   (reusing %s for %s)\n", float64(totalBytesProcessed)/float64(total)*100, status, fi.RelPath)
				mh.SkipFile(fi.RelPath, fi.Size, imported.FileSHA256, imported.SHA256PieceHashes, imported.SHA1PieceHashes)
				totalBytesProcessed += fi.Size
				continue
			}
		}

		f, err := os.Open(full)
		if err != nil {
			log.Fatalf("open %s: %v", full, err)
		}

		var fileBytes int64
		for {
			n, err := f.Read(buf)
			if n > 0 {
				if err := mh.Write(buf[:n]); err != nil {
					f.Close()
					log.Fatalf("processing %s: %v", full, err)
				}
				totalBytesProcessed += int64(n)
				fileBytes += int64(n)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				log.Fatalf("reading %s: %v", full, err)
			}
		}
		f.Close()

		mh.EndFile()

		// Calculate and display progress
		elapsed := time.Since(startTime).Seconds()
		rate := float64(totalBytesProcessed) / elapsed / (1024 * 1024)
		progress := float64(totalBytesProcessed) / float64(total) * 100
		fmt.Printf("  %.1f%% %.1f MiB/s   %s\n", progress, rate, fi.RelPath)
	}

	if canReuseTorrent {
		fmt.Println("Reusing torrent pieces from existing file")
		mh.SetTorrentPieces([]byte(importedTorrent.Info.Pieces))
	} else {
		mh.Finalize()
	}

	// Final statistics
	elapsed := time.Since(startTime).Seconds()
	avgRate := float64(totalBytesProcessed) / elapsed / (1024 * 1024)
	fmt.Printf("\nCompleted in %.2fs (avg %.2f MiB/s)\n", elapsed, avgRate)

	results := mh.GetResults()
	resultMap := make(map[string]FileHashResult)
	for _, r := range results {
		resultMap[r.RelPath] = r
	}

	// Build MetaLink v4
	meta := Metalink{
		XMLNs:   "urn:ietf:params:xml:ns:metalink",
		Version: "4.0",
	}

	baseName := filepath.Base(CLI.Path)
	torrentName := baseName + ".torrent"
	for _, fi := range files {
		r := resultMap[fi.RelPath]

		metaPieceHashes := make([]MetaPieceHash, len(r.SHA256PieceHashes))
		for i, h := range r.SHA256PieceHashes {
			metaPieceHashes[i] = MetaPieceHash{
				Type:  "sha-256",
				Value: h,
			}
		}

		relPath := filepath.ToSlash(fi.RelPath)
		if info.IsDir() {
			relPath = baseName + "/" + filepath.ToSlash(fi.RelPath)
		}

		var urls []MetalinkURL
		for i, m := range CLI.Mirrors {
			u := strings.TrimRight(m, "/") + "/" + escapeURLPath(relPath)
			if !info.IsDir() && strings.HasSuffix(m, fi.RelPath) {
				u = m
			}
			urls = append(urls, MetalinkURL{
				Priority: 10 + i,
				Value:    u,
			})
		}

		mf := MetalinkFile{
			Name: relPath,
			Size: r.Size,
			Hash: MetaHash{
				Type:  "sha-256",
				Value: r.FileSHA256,
			},
			URLs: urls,
			Metaurls: []MetaURL{
				{
					Priority:  1,
					MediaType: "torrent",
					Name:      relPath, // Maps to the file inside the torrent
					Value:     url.PathEscape(torrentName),
				},
			},
		}
		if len(metaPieceHashes) > 0 {
			mf.Pieces = MetaPieces{
				Type:   "sha-256",
				Length: pieceSize,
				Hashes: metaPieceHashes,
			}
		}
		meta.Files = append(meta.Files, mf)
	}

	tor := Torrent{
		Announce: CLI.Tracker,
		Info: TorrentInfo{
			PieceLength: pieceSize,
			Pieces:      string(mh.GetTorrentPieces()),
			Name:        baseName,
		},
	}
	if importedTorrent != nil {
		tor.AnnounceList = importedTorrent.AnnounceList
		tor.URLList = importedTorrent.URLList
		tor.Info.Private = importedTorrent.Info.Private
		tor.Info.Source = importedTorrent.Info.Source
		if CLI.Tracker == "https://privtracker.com/metalink/announce" && importedTorrent.Announce != "" {
			tor.Announce = importedTorrent.Announce
		}
	}

	// Add web seeds (mirrors) to torrent
	if len(CLI.Mirrors) > 0 {
		if info.IsDir() {
			// For multi-file torrents, mirrors should be base URLs
			// the "url-list" must be a root folder where a client could add the "name" and "path/file"
			tor.URLList = make([]string, len(CLI.Mirrors))
			for i, m := range CLI.Mirrors {
				tor.URLList[i] = strings.TrimRight(m, "/") + "/"
			}
		} else {
			// For single-file torrents, mirrors should be full URLs to the file
			tor.URLList = make([]string, len(CLI.Mirrors))
			for i, m := range CLI.Mirrors {
				if strings.HasSuffix(m, baseName) {
					tor.URLList[i] = m
				} else {
					tor.URLList[i] = strings.TrimRight(m, "/") + "/" + url.PathEscape(baseName)
				}
			}
		}
	}

	if info.IsDir() {
		var tFiles []TorrentFileInfo
		for _, fi := range files {
			tFiles = append(tFiles, TorrentFileInfo{
				Length: fi.Size,
				Path:   strings.Split(fi.RelPath, string(os.PathSeparator)),
			})
		}
		tor.Info.Files = tFiles
	} else {
		tor.Info.Length = files[0].Size
	}

	outDir := CLI.OutDir
	if outDir == "" {
		outDir = filepath.Dir(CLI.Path)
		if outDir == "" {
			outDir = "."
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Fatalf("creating outdir: %v", err)
	}

	var generated []string
	if CLI.Modify == "" || torFound {
		torPath := filepath.Join(outDir, torrentName)
		if err := writeTorrentFile(torPath, tor); err != nil {
			log.Fatalf("write torrent: %v", err)
		}
		generated = append(generated, torPath)
	}

	if CLI.Modify == "" || metaFound {
		metaPath := filepath.Join(outDir, baseName+".meta4")
		if err := writeMetaFile(metaPath, meta); err != nil {
			log.Fatalf("write meta4: %v", err)
		}

		if CLI.Sign != "" {
			sig, err := pgpDetachedArmorSign(metaPath, CLI.Sign)
			if err != nil {
				log.Fatalf("pgp sign failed: %v", err)
			}
			meta.Signature = &MetaSignature{
				Mediatype: "application/pgp-signature",
				Value:     sig,
			}
			if err := writeMetaFile(metaPath, meta); err != nil {
				log.Fatalf("write meta4 with signature: %v", err)
			}
		}
		generated = append(generated, metaPath)
	}

	if len(generated) > 0 {
		fmt.Printf("\nGenerated:\n%s\n", strings.Join(generated, "\n"))
	}
}

func writeTorrentFile(path string, t Torrent) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := bencode.Marshal(f, t); err != nil {
		return err
	}
	return nil
}

func writeMetaFile(path string, m Metalink) error {
	out, err := xml.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	out = append([]byte(xml.Header), out...)
	return os.WriteFile(path, out, 0o644)
}

func pgpDetachedArmorSign(filePath string, keyname string) (string, error) {
	args := []string{"--local-user", keyname, "--armor", "--detach-sign", "--output", "-", filePath}

	cmd := exec.Command("gpg", args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gpg failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func escapeURLPath(p string) string {
	segments := strings.Split(p, "/")
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	return strings.Join(segments, "/")
}
