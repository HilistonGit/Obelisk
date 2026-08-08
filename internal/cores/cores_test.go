package cores

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestAssetNameMatchesPublishedNames(t *testing.T) {
	// These are asset names taken from real releases; the mapping exists to
	// produce exactly these strings, so a rename upstream must fail here rather
	// than at download time on a router.
	tests := []struct {
		kind    Kind
		target  string
		version string
		want    string
	}{
		{KindXray, "linux/amd64", "v26.3.27", "Xray-linux-64.zip"},
		{KindXray, "linux/arm64", "v26.3.27", "Xray-linux-arm64-v8a.zip"},
		{KindXray, "linux/arm/7", "v26.3.27", "Xray-linux-arm32-v7a.zip"},
		{KindXray, "linux/arm/5", "v26.3.27", "Xray-linux-arm32-v5.zip"},
		{KindXray, "linux/mipsle", "v26.3.27", "Xray-linux-mips32le.zip"},
		{KindXray, "linux/mips", "v26.3.27", "Xray-linux-mips32.zip"},
		{KindXray, "linux/riscv64", "v26.3.27", "Xray-linux-riscv64.zip"},

		{KindSingBox, "linux/amd64", "v1.13.16", "sing-box-1.13.16-linux-amd64.tar.gz"},
		{KindSingBox, "linux/arm64", "v1.13.16", "sing-box-1.13.16-linux-arm64.tar.gz"},
		{KindSingBox, "linux/arm/7", "v1.13.16", "sing-box-1.13.16-linux-armv7.tar.gz"},
		{KindSingBox, "linux/arm/6", "v1.13.16", "sing-box-1.13.16-linux-armv6.tar.gz"},
		{KindSingBox, "linux/mipsle", "v1.13.16", "sing-box-1.13.16-linux-mipsle-softfloat.tar.gz"},
		{KindSingBox, "linux/mips", "v1.13.16", "sing-box-1.13.16-linux-mips-softfloat.tar.gz"},
		{KindSingBox, "linux/riscv64", "v1.13.16", "sing-box-1.13.16-linux-riscv64.tar.gz"},
	}

	for _, tc := range tests {
		t.Run(string(tc.kind)+" "+tc.target, func(t *testing.T) {
			target, err := ParseTarget(tc.target)
			if err != nil {
				t.Fatalf("ParseTarget: %v", err)
			}
			got, err := AssetName(tc.kind, target, tc.version)
			if err != nil {
				t.Fatalf("AssetName: %v", err)
			}
			if got != tc.want {
				t.Errorf("AssetName = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSingBoxPicksTheBuildThatActuallyStarts(t *testing.T) {
	// Found on a real OpenWrt router: the default sing-box build fails to exec
	// with ENOENT on musl — the kernel reporting a dynamic loader it cannot
	// find, which reads like a missing file and is not. OpenWrt and Alpine are
	// both musl, so this covers routers and the container image alike.
	tests := []struct {
		target string
		want   string
	}{
		{"linux/arm64/musl", "sing-box-1.13.16-linux-arm64-musl.tar.gz"},
		{"linux/arm64/gnu", "sing-box-1.13.16-linux-arm64.tar.gz"},
		{"linux/amd64/musl", "sing-box-1.13.16-linux-amd64-musl.tar.gz"},
		{"linux/arm/7/musl", "sing-box-1.13.16-linux-armv7-musl.tar.gz"},
		{"linux/mipsle/softfloat/musl", "sing-box-1.13.16-linux-mipsle-softfloat-musl.tar.gz"},
		// No musl build is published for these, so the default is the only
		// option and asking for musl must not invent a nonexistent asset.
		{"linux/arm/6/musl", "sing-box-1.13.16-linux-armv6.tar.gz"},
		{"linux/mips/softfloat/musl", "sing-box-1.13.16-linux-mips-softfloat.tar.gz"},
	}

	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			target, err := ParseTarget(tc.target)
			if err != nil {
				t.Fatalf("ParseTarget: %v", err)
			}
			got, err := AssetName(KindSingBox, target, "v1.13.16")
			if err != nil {
				t.Fatalf("AssetName: %v", err)
			}
			if got != tc.want {
				t.Errorf("AssetName = %q, want %q", got, tc.want)
			}
		})
	}

	// Xray publishes one build per architecture with no libc variants, so the
	// C library must not leak into its asset name.
	musl, _ := ParseTarget("linux/arm64/musl")
	gnu, _ := ParseTarget("linux/arm64/gnu")
	a, _ := AssetName(KindXray, musl, "v26.3.27")
	b, _ := AssetName(KindXray, gnu, "v26.3.27")
	if a != b || a != "Xray-linux-arm64-v8a.zip" {
		t.Errorf("Xray asset should not depend on libc: %q vs %q", a, b)
	}
}

func TestAssetNameRejectsNonLinux(t *testing.T) {
	target, _ := ParseTarget("windows/amd64")
	if _, err := AssetName(KindXray, target, "v26.3.27"); err == nil {
		t.Error("expected an error for a non-linux target")
	}
}

func TestParseTargetDefaults(t *testing.T) {
	arm, err := ParseTarget("linux/arm")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	// ARMv7 is the safe default: every ARM router of the last decade runs it.
	if arm.GOARM != "7" {
		t.Errorf("GOARM = %q, want 7 by default", arm.GOARM)
	}

	mips, err := ParseTarget("linux/mipsle")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	// OpenWrt builds its MIPS targets softfloat, and so does sing-box.
	if mips.GOMIPS != "softfloat" {
		t.Errorf("GOMIPS = %q, want softfloat by default", mips.GOMIPS)
	}

	if _, err := ParseTarget("nonsense"); err == nil {
		t.Error("expected an error for a target without a slash")
	}
}

func TestChecksumAvailability(t *testing.T) {
	// Xray ships a digest next to every archive; sing-box ships none at all, and
	// pretending otherwise would make an unverified install look verified.
	if got := ChecksumAssetName(KindXray, "Xray-linux-arm64-v8a.zip"); got != "Xray-linux-arm64-v8a.zip.dgst" {
		t.Errorf("ChecksumAssetName = %q", got)
	}
	if got := ChecksumAssetName(KindSingBox, "sing-box-1.13.16-linux-arm64.tar.gz"); got != "" {
		t.Errorf("ChecksumAssetName = %q, want empty for sing-box", got)
	}
}

func TestParseSHA256(t *testing.T) {
	// The real layout of an Xray .dgst file.
	dgst := "MD5= 82cba68865b29a56d332f5ffbb1bffeb3\n" +
		"SHA1= b21adcc9aefbca432887fcdc492e3733131831ad\n" +
		"SHA2-256= 4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c\n" +
		"SHA2-512= 8c97796fd1acc4e95a73df7e4c3de4908219b5da872175ddaef34275aa9859d9\n"

	got, err := parseSHA256([]byte(dgst))
	if err != nil {
		t.Fatalf("parseSHA256: %v", err)
	}
	want := "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c"
	if got != want {
		t.Errorf("parseSHA256 = %q, want %q", got, want)
	}

	// The conventional sha256sum layout must also work, so that a project
	// switching formats does not silently disable verification.
	sum := want + "  Xray-linux-arm64-v8a.zip\n"
	if got, err := parseSHA256([]byte(sum)); err != nil || got != want {
		t.Errorf("sha256sum layout: got %q, %v", got, err)
	}

	// A file with only an MD5 must be an error, never a false positive.
	if _, err := parseSHA256([]byte("MD5= 82cba68865b29a56d332f5ffbb1bffeb3\n")); err == nil {
		t.Error("expected an error when no SHA-256 digest is present")
	}
}

func TestExtractFromZip(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "Xray-linux-64.zip")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"README.md": "not the binary",
		"geoip.dat": "not the binary either",
		"xray":      "#!/bin/true\n",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "xray")
	if err := extractBinary(archive, "Xray-linux-64.zip", "xray", dest); err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "#!/bin/true\n" {
		t.Errorf("extracted %q, want the xray entry", got)
	}
}

func TestExtractFromTarGz(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "sing-box-1.13.16-linux-arm64.tar.gz")

	// sing-box nests the binary inside a version-named directory.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	entries := []struct {
		name    string
		content string
	}{
		{"sing-box-1.13.16-linux-arm64/LICENSE", "licence text"},
		{"sing-box-1.13.16-linux-arm64/sing-box", "binary content"},
	}
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: e.name, Mode: 0o755, Size: int64(len(e.content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "sing-box")
	if err := extractBinary(archive, filepath.Base(archive), "sing-box", dest); err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "binary content" {
		t.Errorf("extracted %q", got)
	}
}

func TestExtractMissingBinaryIsAnError(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "empty.zip")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("README.md")
	_, _ = w.Write([]byte("nothing useful"))
	_ = zw.Close()
	if err := os.WriteFile(archive, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := extractBinary(archive, "empty.zip", "xray", filepath.Join(dir, "xray")); err == nil {
		t.Error("expected an error when the archive holds no binary")
	}
}

func TestSwapInKeepsABackup(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{Dir: dir}

	current := m.binaryPath(KindXray)
	if err := os.WriteFile(current, []byte("old version"), 0o755); err != nil {
		t.Fatal(err)
	}
	staged := current + ".new"
	if err := os.WriteFile(staged, []byte("new version"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := m.swapIn(KindXray, staged); err != nil {
		t.Fatalf("swapIn: %v", err)
	}

	if got, _ := os.ReadFile(current); string(got) != "new version" {
		t.Errorf("current binary = %q", got)
	}
	// The previous binary must survive: on a router, rolling back is the only
	// recovery path when the new core cannot reach the network.
	if got, _ := os.ReadFile(m.backupPath(KindXray)); string(got) != "old version" {
		t.Errorf("backup = %q, want the previous binary", got)
	}
}

func TestNormalizeVersion(t *testing.T) {
	// Release tags carry a "v", the binaries report the bare number, and the two
	// must compare equal or every status check would claim an update is due.
	if normalizeVersion("v1.13.16") != normalizeVersion("1.13.16") {
		t.Error("a tag and a reported version must normalize to the same string")
	}
	if normalizeVersion("v26.3.27") != "26.3.27" {
		t.Errorf("normalizeVersion = %q", normalizeVersion("v26.3.27"))
	}
}

func TestVersionPatternMatchesBothCores(t *testing.T) {
	// The two cores word their version output completely differently.
	tests := map[string]string{
		"Xray 26.3.27 (Xray, Penetrates Everything.) Custom":          "26.3.27",
		"sing-box version 1.13.16\n\nEnvironment: go1.24 linux/arm64": "1.13.16",
	}
	for output, want := range tests {
		if got := versionPattern.FindString(output); got != want {
			t.Errorf("versionPattern on %q = %q, want %q", output, got, want)
		}
	}
}
