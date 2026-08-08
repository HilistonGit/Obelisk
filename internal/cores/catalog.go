// Package cores installs and updates the proxy cores Obelisk drives.
//
// The cores are never linked into Obelisk. They stay independent executables on
// disk, which is the whole point: a new Xray or sing-box release is a file swap,
// not a rebuild of the client. This package owns that swap — locating the right
// release asset for the running architecture, verifying what it downloaded,
// replacing the binary atomically, and keeping the previous one for rollback.
package cores

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// Kind identifies one of the two cores.
type Kind string

const (
	KindXray    Kind = "xray"
	KindSingBox Kind = "sing-box"
)

// AllKinds lists every core Obelisk can install, in stable order.
var AllKinds = []Kind{KindSingBox, KindXray}

// ParseKind normalizes a core name from the command line.
func ParseKind(s string) (Kind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "xray", "xray-core":
		return KindXray, nil
	case "sing-box", "singbox", "sb":
		return KindSingBox, nil
	default:
		return "", fmt.Errorf("unknown core %q (expected xray or sing-box)", s)
	}
}

// Repo returns the GitHub repository a core is released from.
func (k Kind) Repo() string {
	switch k {
	case KindXray:
		return "XTLS/Xray-core"
	case KindSingBox:
		return "SagerNet/sing-box"
	default:
		return ""
	}
}

// BinaryName returns the executable's name inside the release archive, which is
// also the name Obelisk installs it under.
func (k Kind) BinaryName() string { return string(k) }

// Target is the platform an asset is being selected for. It defaults to the
// platform Obelisk itself is running on, but stays explicit so that a build host
// can fetch cores for a different router.
type Target struct {
	GOOS   string
	GOARCH string
	GOARM  string // "5", "6" or "7"; only meaningful when GOARCH is "arm"
	GOMIPS string // "softfloat" or "hardfloat"; only for the mips family

	// Libc is "musl" or "gnu".
	//
	// It matters because sing-box publishes separate builds for each, and the
	// difference is not cosmetic: the default build refuses to start on a musl
	// system with ENOENT — the kernel reporting a missing dynamic loader, not a
	// missing file. OpenWrt and Alpine are both musl, which covers routers and
	// the container image alike, so getting this wrong breaks the two places
	// Obelisk is actually meant to run.
	Libc string
}

// Libc values.
const (
	LibcMusl = "musl"
	LibcGNU  = "gnu"
)

// CurrentTarget describes the platform Obelisk is running on.
//
// GOARM and GOMIPS are not observable at runtime — a binary compiled for ARMv7
// does not carry that fact in a way the standard library exposes — so the safe
// defaults are used: ARMv7, which every ARM router made this decade supports,
// and softfloat, which is what OpenWrt builds its MIPS targets with.
func CurrentTarget() Target {
	t := Target{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Libc: DetectLibc()}
	switch t.GOARCH {
	case "arm":
		t.GOARM = "7"
	case "mips", "mipsle", "mips64", "mips64le":
		t.GOMIPS = "softfloat"
	}
	return t
}

// DetectLibc reports which C library this system provides.
//
// Obelisk itself is pure Go and does not care, but the cores it downloads do.
// The check is for musl's dynamic loader, which exists at a predictable path on
// every musl system and on no glibc one.
func DetectLibc() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	if matches, err := filepath.Glob("/lib/ld-musl-*.so.1"); err == nil && len(matches) > 0 {
		return LibcMusl
	}
	return LibcGNU
}

// ParseTarget reads a platform written the way Go names them: "linux/arm64",
// "linux/arm/7", "linux/mipsle/softfloat". This is what lets a build host or a
// workstation fetch cores for the router they are being prepared for.
func ParseTarget(s string) (Target, error) {
	parts := strings.Split(strings.TrimSpace(s), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return Target{}, fmt.Errorf("target %q is not in os/arch form", s)
	}

	t := Target{GOOS: parts[0], GOARCH: parts[1]}

	// A trailing "musl" or "gnu" names the C library; anything else in that
	// position is the architecture variant.
	rest := parts[2:]
	if n := len(rest); n > 0 && (rest[n-1] == LibcMusl || rest[n-1] == LibcGNU) {
		t.Libc = rest[n-1]
		rest = rest[:n-1]
	}
	variant := ""
	if len(rest) > 0 {
		variant = rest[0]
	}

	switch t.GOARCH {
	case "arm":
		t.GOARM = variant
		if t.GOARM == "" {
			t.GOARM = "7"
		}
	case "mips", "mipsle", "mips64", "mips64le":
		t.GOMIPS = variant
		if t.GOMIPS == "" {
			t.GOMIPS = "softfloat"
		}
	}
	return t, nil
}

// Equal reports whether two targets name the same platform.
func (t Target) Equal(other Target) bool {
	return t.GOOS == other.GOOS && t.GOARCH == other.GOARCH &&
		t.GOARM == other.GOARM && t.GOMIPS == other.GOMIPS &&
		t.Libc == other.Libc
}

// String renders the target the way Go names platforms.
func (t Target) String() string {
	s := t.GOOS + "/" + t.GOARCH
	if t.GOARM != "" {
		s += "v" + t.GOARM
	}
	if t.GOMIPS != "" {
		s += "-" + t.GOMIPS
	}
	if t.Libc != "" {
		s += " (" + t.Libc + ")"
	}
	return s
}

// AssetName returns the release asset a core publishes for this target.
//
// The two projects name their assets on completely different systems — Xray by
// bit width and ARM revision ("Xray-linux-arm64-v8a.zip"), sing-box by Go's own
// architecture names with the version embedded
// ("sing-box-1.13.16-linux-arm64.tar.gz") — so both mappings live here, and this
// is the only file that needs touching if either project renames anything.
func AssetName(k Kind, t Target, version string) (string, error) {
	if t.GOOS != "linux" {
		return "", fmt.Errorf("%s: Obelisk only installs cores for linux, not %q", k, t.GOOS)
	}

	switch k {
	case KindXray:
		arch, err := xrayArch(t)
		if err != nil {
			return "", err
		}
		return "Xray-linux-" + arch + ".zip", nil

	case KindSingBox:
		arch, err := singboxArch(t)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("sing-box-%s-linux-%s.tar.gz", strings.TrimPrefix(version, "v"), arch), nil

	default:
		return "", fmt.Errorf("unknown core %q", k)
	}
}

// ChecksumAssetName returns the asset carrying the publisher's checksum, or an
// empty string when the project does not publish one.
//
// Xray ships a ".dgst" file next to every archive. sing-box publishes no
// checksums at all, so an installed sing-box is only as trustworthy as the TLS
// connection it arrived over. Obelisk records the hash it installed either way,
// which does not make the download more trustworthy but does let a later check
// notice if the file changed on disk afterwards.
func ChecksumAssetName(k Kind, asset string) string {
	switch k {
	case KindXray:
		return asset + ".dgst"
	default:
		return ""
	}
}

// xrayArch maps a Go target onto Xray's architecture spelling.
func xrayArch(t Target) (string, error) {
	switch t.GOARCH {
	case "amd64":
		return "64", nil
	case "386":
		return "32", nil
	case "arm64":
		return "arm64-v8a", nil
	case "arm":
		switch t.GOARM {
		case "5":
			return "arm32-v5", nil
		case "6":
			return "arm32-v6", nil
		default:
			return "arm32-v7a", nil
		}
	case "mips":
		return "mips32", nil
	case "mipsle":
		return "mips32le", nil
	case "mips64":
		return "mips64", nil
	case "mips64le":
		return "mips64le", nil
	case "riscv64":
		return "riscv64", nil
	case "ppc64":
		return "ppc64", nil
	case "ppc64le":
		return "ppc64le", nil
	case "s390x":
		return "s390x", nil
	case "loong64":
		return "loong64", nil
	default:
		return "", fmt.Errorf("xray publishes no linux build for %s", t.GOARCH)
	}
}

// muslVariants are the architectures sing-box publishes a musl build for.
// Anything absent here has only the default build, which is then the only
// option whatever the system's C library is.
var muslVariants = map[string]bool{
	"386": true, "amd64": true, "arm64": true, "armv7": true,
	"mipsle-softfloat": true, "riscv64": true, "loong64": true,
}

// singboxArch maps a Go target onto sing-box's architecture spelling, choosing
// the build that will actually start on the target's C library.
func singboxArch(t Target) (string, error) {
	base, err := singboxBaseArch(t)
	if err != nil {
		return "", err
	}
	// On a musl system the default build fails to exec with ENOENT — the kernel
	// reporting a dynamic loader it cannot find. Where a musl build exists it is
	// therefore mandatory, not preferable.
	if t.Libc == LibcMusl && muslVariants[base] {
		return base + "-musl", nil
	}
	return base, nil
}

func singboxBaseArch(t Target) (string, error) {
	switch t.GOARCH {
	case "amd64", "386", "arm64", "riscv64", "s390x", "ppc64le", "loong64":
		return t.GOARCH, nil
	case "arm":
		switch t.GOARM {
		case "5":
			return "armv5", nil
		case "6":
			return "armv6", nil
		default:
			return "armv7", nil
		}
	case "mips", "mipsle", "mips64le":
		// sing-box only publishes softfloat builds for the 32-bit MIPS targets,
		// which is also the only thing OpenWrt runs on them.
		return t.GOARCH + "-softfloat", nil
	case "mips64":
		return "mips64-softfloat", nil
	default:
		return "", fmt.Errorf("sing-box publishes no linux build for %s", t.GOARCH)
	}
}
