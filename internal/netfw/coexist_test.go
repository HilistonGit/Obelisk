package netfw

import (
	"context"
	"fmt"
	"testing"
)

// tableRunner answers "nft list tables" with a fixed list.
type tableRunner struct {
	tables string
	fail   bool
}

func (r tableRunner) Run(context.Context, string, []string, string) (string, error) {
	if r.fail {
		return "", fmt.Errorf("nft: not found")
	}
	return r.tables, nil
}

func TestDetectZapret(t *testing.T) {
	cases := []struct {
		name   string
		runner tableRunner
		want   bool
	}{
		{"zapret present", tableRunner{tables: "table inet fw4\ntable inet zapret\ntable ip nat\n"}, true},
		{"nothing but the firewall", tableRunner{tables: "table inet fw4\ntable ip nat\n"}, false},
		{"a table merely named similarly", tableRunner{tables: "table inet fw4\ntable inet zapretx\n"}, false},
		{"no nft at all", tableRunner{fail: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := NewWithRunner(DefaultConfig(), c.runner)
			out, err := m.runner.Run(context.Background(), "nft", []string{"list", "tables"}, "")
			present := err == nil && detectZapretIn(out)
			if present != c.want {
				t.Errorf("detected=%v, want %v", present, c.want)
			}
		})
	}
}

// The exemption has to set exactly the bit zapret gates on, and leave the rest
// of the mark alone — the same mark is what keeps the core's own sockets out of
// Obelisk's TPROXY capture, and losing that would feed the core back into itself.
func TestZapretExemptPreservesTheOriginalMark(t *testing.T) {
	const own = DefaultBypassMark

	exempt := WithZapretExempt(own)
	if exempt&ZapretExemptBit == 0 {
		t.Error("the exemption bit was not set")
	}
	if exempt&own != own {
		t.Errorf("the original mark %#x did not survive: %#x", own, exempt)
	}
	if !HasZapretExempt(exempt) {
		t.Error("HasZapretExempt disagrees with WithZapretExempt")
	}
	if HasZapretExempt(own) {
		t.Error("a plain mark was reported as already exempt")
	}
	// Applying it twice must not drift.
	if WithZapretExempt(exempt) != exempt {
		t.Error("the exemption is not idempotent")
	}
}
