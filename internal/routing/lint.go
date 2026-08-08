package routing

import (
	"fmt"
	"net"
	"strings"
)

// Conflict reports a rule that can never take effect because an earlier rule
// already matches everything it would.
//
// This is the sharpest edge in first-match-wins routing, and it is invisible
// until something does not work. A user who adds "youtube.com → tunnel" and then
// "ads.youtube.com → block" has written two reasonable-looking rules of which
// the second is dead: the first already claimed every name under youtube.com.
// The fix is to move the specific rule above the general one, and the only way a
// user can know that is if something tells them.
type Conflict struct {
	Index      int   `json:"index"`
	Entry      Entry `json:"entry"`
	ShadowedBy int   `json:"shadowed_by"`
	By         Entry `json:"by"`

	// Harmful marks the case where the two rules disagree about what to do, so
	// the shadowing changes the outcome rather than merely repeating it.
	Harmful bool   `json:"harmful"`
	Reason  string `json:"reason"`
}

// FindShadowed returns every rule that an earlier rule makes unreachable.
//
// It only reports cases it is certain about. A false alarm would teach users to
// ignore the warnings, which is worse than staying quiet about a rule that might
// be fine.
func FindShadowed(entries []Entry) []Conflict {
	var conflicts []Conflict

	for i := range entries {
		later := entries[i]
		if !later.Enabled {
			continue
		}
		for j := 0; j < i; j++ {
			earlier := entries[j]
			if !earlier.Enabled || !scopeCovers(earlier, later) {
				continue
			}
			if !covers(earlier, later) {
				continue
			}

			harmful := earlier.Action != later.Action || earlier.Target != later.Target
			reason := fmt.Sprintf("rule #%d (%s) already matches everything #%d (%s) would",
				j+1, earlier.Value, i+1, later.Value)
			if harmful {
				reason += fmt.Sprintf(", so traffic goes %s instead of %s", earlier.Action, later.Action)
			} else {
				reason += "; it is redundant"
			}

			conflicts = append(conflicts, Conflict{
				Index:      i,
				Entry:      later,
				ShadowedBy: j,
				By:         earlier,
				Harmful:    harmful,
				Reason:     reason,
			})
			break // one explanation per rule is enough
		}
	}
	return conflicts
}

// covers reports whether every destination matched by b is also matched by a.
func covers(a, b Entry) bool {
	switch a.Kind {
	case KindDomainSuffix:
		if !isDomainKind(b.Kind) {
			return false
		}
		// A suffix covers itself and anything beneath it.
		return b.Value == a.Value || strings.HasSuffix(b.Value, "."+a.Value)

	case KindDomainExact:
		// An exact name covers only the identical exact name.
		return b.Kind == KindDomainExact && b.Value == a.Value

	case KindDomainKeyword:
		// A keyword covers any domain whose text contains it. A suffix rule
		// beneath it is dead, because every name it matches contains the keyword.
		if b.Kind != KindDomainSuffix && b.Kind != KindDomainExact && b.Kind != KindDomainKeyword {
			return false
		}
		return strings.Contains(b.Value, a.Value)

	case KindIPCIDR:
		if b.Kind != KindIPCIDR {
			return false
		}
		return cidrContains(a.Value, b.Value)

	default:
		// Regular expressions and external lists cannot be reasoned about
		// cheaply, and guessing would produce false alarms.
		return false
	}
}

func isDomainKind(k MatchKind) bool {
	return k == KindDomainSuffix || k == KindDomainExact
}

// cidrContains reports whether network a fully contains network b.
func cidrContains(a, b string) bool {
	_, netA, err := net.ParseCIDR(a)
	if err != nil {
		return false
	}
	ipB, netB, err := net.ParseCIDR(b)
	if err != nil {
		return false
	}
	if !netA.Contains(ipB) {
		return false
	}
	// Containing the base address is not enough; a must also be no narrower.
	onesA, bitsA := netA.Mask.Size()
	onesB, bitsB := netB.Mask.Size()
	return bitsA == bitsB && onesA <= onesB
}

// scopeCovers reports whether a applies to at least every client b applies to.
func scopeCovers(a, b Entry) bool {
	if len(a.Sources) == 0 {
		return true // unscoped rules apply to everyone
	}
	if len(b.Sources) == 0 {
		return false
	}
	for _, want := range b.Sources {
		found := false
		for _, have := range a.Sources {
			if have == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
