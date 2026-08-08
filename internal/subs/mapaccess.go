package subs

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// The Clash and sing-box parsers both walk loosely-typed documents: YAML and
// JSON alike are decoded into map[string]any so that a panel emitting a port as
// "443" instead of 443, or spelling a key "servername" instead of "sni", costs a
// coercion rather than a failed unmarshal into a rigid struct. These accessors
// are the coercion layer, shared by both parsers.

// mStr returns the first key present in the map, coerced to a trimmed string.
func mStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if s := strings.TrimSpace(t); s != "" {
				return s
			}
		case bool:
			return strconv.FormatBool(t)
		case int:
			return strconv.Itoa(t)
		case int64:
			return strconv.FormatInt(t, 10)
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64)
		case json.Number:
			return t.String()
		}
	}
	return ""
}

// mInt returns the first key present in the map, coerced to an int.
func mInt(m map[string]any, keys ...string) int {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case int:
			return t
		case int64:
			return int(t)
		case float64:
			return int(t)
		case json.Number:
			if i, err := t.Int64(); err == nil {
				return int(i)
			}
		case string:
			if i, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
				return i
			}
		}
	}
	return 0
}

// mBool returns the first key present in the map, coerced to a bool. Panels emit
// "true", "1" and yes/on interchangeably.
func mBool(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case bool:
			return t
		case string:
			return parseBool(t)
		case int:
			return t != 0
		case float64:
			return t != 0
		}
	}
	return false
}

// mStrSlice returns the first key present in the map as a string slice,
// accepting both a real list and a comma-separated scalar.
func mStrSlice(m map[string]any, keys ...string) []string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case []any:
			out := make([]string, 0, len(t))
			for _, item := range t {
				if s := fmt.Sprintf("%v", item); strings.TrimSpace(s) != "" {
					out = append(out, strings.TrimSpace(s))
				}
			}
			if len(out) > 0 {
				return out
			}
		case []string:
			if len(t) > 0 {
				return t
			}
		case string:
			if s := splitList(t); len(s) > 0 {
				return s
			}
		}
	}
	return nil
}

// mIntSlice returns the first key present in the map as an int slice.
func mIntSlice(m map[string]any, keys ...string) []int {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		if list, ok := v.([]any); ok {
			out := make([]int, 0, len(list))
			for _, item := range list {
				switch t := item.(type) {
				case int:
					out = append(out, t)
				case float64:
					out = append(out, int(t))
				case string:
					out = append(out, atoiOr(t, 0))
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

// mMap returns a nested mapping, normalizing the map[any]any that older YAML
// documents can produce.
func mMap(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case map[string]any:
			return t
		case map[any]any:
			out := make(map[string]any, len(t))
			for key, val := range t {
				out[fmt.Sprintf("%v", key)] = val
			}
			return out
		}
	}
	return nil
}

// mStrMap returns a nested mapping flattened to string values, which is what
// transport header blocks always are.
func mStrMap(m map[string]any, keys ...string) map[string]string {
	nested := mMap(m, keys...)
	if len(nested) == 0 {
		return nil
	}
	out := make(map[string]string, len(nested))
	for k, v := range nested {
		switch t := v.(type) {
		case []any:
			if len(t) > 0 {
				out[k] = fmt.Sprintf("%v", t[0])
			}
		default:
			out[k] = strings.TrimSpace(fmt.Sprintf("%v", v))
		}
	}
	return out
}

// mList returns a list of mappings, which is how both formats express their
// arrays of proxies or outbounds.
func mList(m map[string]any, keys ...string) []map[string]any {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		list, ok := v.([]any)
		if !ok {
			continue
		}
		out := make([]map[string]any, 0, len(list))
		for _, item := range list {
			switch t := item.(type) {
			case map[string]any:
				out = append(out, t)
			case map[any]any:
				norm := make(map[string]any, len(t))
				for key, val := range t {
					norm[fmt.Sprintf("%v", key)] = val
				}
				out = append(out, norm)
			}
		}
		return out
	}
	return nil
}
