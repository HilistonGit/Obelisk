package cores

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// maxBinarySize caps how much will be written while extracting one file. The
// cores are around 10-30 MB; anything an order of magnitude past that is either
// a broken download or a decompression bomb, and a router has no memory or flash
// to spare for finding out which.
const maxBinarySize = 256 << 20

// extractBinary pulls a single named executable out of a release archive and
// writes it to destPath. The archive format is taken from the asset name, which
// is the publisher's own and therefore more reliable than sniffing.
func extractBinary(archivePath, assetName, binaryName, destPath string) error {
	switch {
	case strings.HasSuffix(assetName, ".zip"):
		return extractFromZip(archivePath, binaryName, destPath)
	case strings.HasSuffix(assetName, ".tar.gz"), strings.HasSuffix(assetName, ".tgz"):
		return extractFromTarGz(archivePath, binaryName, destPath)
	default:
		return fmt.Errorf("unsupported archive format for %q", assetName)
	}
}

// extractFromZip handles Xray's release archives, which hold the executable at
// the archive root alongside the geo databases and the licence.
func extractFromZip(archivePath, binaryName, destPath string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		if path.Base(f.Name) != binaryName || f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open %s in archive: %w", binaryName, err)
		}
		defer rc.Close()
		return writeExecutable(destPath, rc)
	}
	return fmt.Errorf("archive contains no file named %q", binaryName)
}

// extractFromTarGz handles sing-box's release archives, which nest the
// executable inside a directory named after the version.
func extractFromTarGz(archivePath, binaryName, destPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("read archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || path.Base(hdr.Name) != binaryName {
			continue
		}
		return writeExecutable(destPath, tr)
	}
	return fmt.Errorf("archive contains no file named %q", binaryName)
}

// writeExecutable copies an extracted file to disk with the executable bit set.
func writeExecutable(destPath string, src io.Reader) error {
	out, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create %s: %w", destPath, err)
	}
	defer out.Close()

	written, err := io.Copy(out, io.LimitReader(src, maxBinarySize+1))
	if err != nil {
		return fmt.Errorf("write %s: %w", destPath, err)
	}
	if written > maxBinarySize {
		return fmt.Errorf("extracted file exceeds %d bytes", maxBinarySize)
	}
	if written == 0 {
		return fmt.Errorf("extracted file is empty")
	}

	// The umask can clear the bits handed to OpenFile, and a core that is not
	// executable fails at launch with an error that points nowhere useful.
	if err := out.Chmod(0o755); err != nil {
		return fmt.Errorf("chmod %s: %w", destPath, err)
	}
	return out.Sync()
}

// parseSHA256 extracts the SHA-256 digest from a checksum file.
//
// Xray publishes a ".dgst" file listing several digests, one per line, in the
// form "SHA2-256= <hex>". The sha256sum layout ("<hex>  <filename>") is accepted
// too, so that a project switching to the conventional format does not break
// verification.
func parseSHA256(data []byte) (string, error) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if label, value, ok := strings.Cut(line, "="); ok {
			switch strings.ToUpper(strings.TrimSpace(label)) {
			case "SHA2-256", "SHA256", "SHA-256":
				if digest, ok := validHex(strings.TrimSpace(value), 32); ok {
					return digest, nil
				}
			}
			continue
		}

		// "<hex>  <filename>"
		if fields := strings.Fields(line); len(fields) >= 1 {
			if digest, ok := validHex(fields[0], 32); ok {
				return digest, nil
			}
		}
	}
	return "", fmt.Errorf("checksum file contains no SHA-256 digest")
}

// validHex reports whether s is a hex string decoding to exactly n bytes.
func validHex(s string, n int) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	decoded, err := hex.DecodeString(s)
	if err != nil || len(decoded) != n {
		return "", false
	}
	return s, true
}
