// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package revsym provides a COMPLETE reflection dump of an arbitrary Go value --
// including unexported fields, map contents, pointer sharing and float bit
// patterns -- so two program states can be compared for exact equality.
//
// It exists to measure reorg revert-symmetry. The hand-written comparators used by
// the shipped rollback suites (test/unit/dposkeyframe_test.go producerEqual,
// stateKeyFrameEqual, committeeKeyFrameEqual) compare a hand-picked subset of
// fields and compare several maps by len() only, so they are structurally blind to
// exactly the fields the Class-E revert-symmetry fixes touch (workedInRound,
// inactiveCountV2, DposV2EffectedProducers, DepositOutputs values, UsedDposV2Votes,
// DPoSV2ActiveHeight, Snapshots). A comparison that cannot fail proves nothing.
//
// Test-only: nothing in the production tree imports this package.
package revsym

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unsafe"
)

// Options controls what the dumper walks.
type Options struct {
	// SkipTypes holds reflect.Type.String() values that are not descended into.
	// Use for shared immutable config and for lock types.
	SkipTypes map[string]bool

	// SkipFields holds "pkg.Type.FieldName" entries that are not descended into.
	// Use ONLY for values that are monotonic by design (never restored by a
	// rollback) -- every such entry weakens the measurement and must be justified.
	SkipFields map[string]bool

	// MaxDepth bounds recursion; a hit is emitted as a <maxdepth> marker so it
	// can never silently hide a difference.
	MaxDepth int

	// Identity additionally emits a per-pointer identity line, so a change in the
	// object GRAPH (two maps that aliased the same object now holding two equal
	// copies) is visible. Off by default: consensus state is compared by VALUE --
	// keyframes and checkpoints serialize values, not aliasing -- and reachable
	// values are always fully expanded whether Identity is on or off.
	Identity bool

	// StrictNil distinguishes a nil map/slice from an empty one. Off by default:
	// the two are indistinguishable to every read path and serialize identically,
	// and a keyframe/checkpoint serialize-deserialize round trip (which a round
	// change performs on the CRC arbiter set) turns nil into empty unconditionally.
	StrictNil bool
}

// NewOptions returns options that skip only lock types (whose internal state is
// not derived consensus state) and bound depth.
func NewOptions() Options {
	return Options{
		SkipTypes: map[string]bool{
			"sync.Mutex":     true,
			"sync.RWMutex":   true,
			"sync.WaitGroup": true,
			"sync.Once":      true,
			"sync.Map":       true,
		},
		SkipFields: map[string]bool{},
		MaxDepth:   60,
	}
}

// Skip marks a reflect type string as not-walked.
func (o Options) Skip(types ...string) Options {
	for _, t := range types {
		o.SkipTypes[t] = true
	}
	return o
}

// SkipField marks "pkg.Type.Field" as not-walked.
func (o Options) SkipField(fields ...string) Options {
	for _, f := range fields {
		o.SkipFields[f] = true
	}
	return o
}

type ptrKey struct {
	p unsafe.Pointer
	t reflect.Type
}

type dumper struct {
	opt   Options
	lines []string
	ids   map[ptrKey]int
	next  int
	// onPath holds the pointers on the CURRENT path only, so a cycle is cut but a
	// DAG (a producer held by three maps) is fully expanded under every path that
	// reaches it. Nothing reachable is ever compared by identity alone.
	onPath map[ptrKey]bool
	budget int
}

// Dump renders v -- and everything reachable from it -- as a deterministic,
// line-per-leaf "path = value" listing.
func Dump(v interface{}, opt Options) string {
	d := &dumper{opt: opt, ids: map[ptrKey]int{}, onPath: map[ptrKey]bool{}, budget: 4000000}
	d.walk("$", reflect.ValueOf(v), 0)
	return strings.Join(d.lines, "\n")
}

func (d *dumper) emit(path, val string) {
	d.budget--
	if d.budget < 0 {
		panic("revsym: dump budget exhausted -- the value graph is larger than expected")
	}
	d.lines = append(d.lines, path+" = "+val)
}

// expose returns an addressable, non-read-only view of an unexported field so it
// can be read. Requires v.CanAddr(), which walk guarantees by copying any
// non-addressable struct into a fresh addressable cell before descending.
func expose(v reflect.Value) reflect.Value {
	if !v.CanAddr() {
		return v
	}
	return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
}

func byteString(v reflect.Value) string {
	const hexdigits = "0123456789abcdef"
	n := v.Len()
	buf := make([]byte, 0, n*2)
	for i := 0; i < n; i++ {
		b := byte(v.Index(i).Uint())
		buf = append(buf, hexdigits[b>>4], hexdigits[b&0x0f])
	}
	return string(buf)
}

func (d *dumper) walk(path string, v reflect.Value, depth int) {
	if !v.IsValid() {
		d.emit(path, "<invalid>")
		return
	}
	if depth > d.opt.MaxDepth {
		d.emit(path, "<maxdepth>")
		return
	}
	t := v.Type()
	if d.opt.SkipTypes[t.String()] {
		d.emit(path, "<skip "+t.String()+">")
		return
	}

	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			d.emit(path, "nil")
			return
		}
		k := ptrKey{v.UnsafePointer(), t}
		if d.onPath[k] {
			d.emit(path, "<cycle>")
			return
		}
		if d.opt.Identity {
			id, ok := d.ids[k]
			if !ok {
				d.next++
				d.ids[k] = d.next
				id = d.next
			}
			d.emit(path+"#id", strconv.Itoa(id))
		}
		d.onPath[k] = true
		d.walk(path+"*", v.Elem(), depth+1)
		delete(d.onPath, k)

	case reflect.Interface:
		if v.IsNil() {
			d.emit(path, "nil-iface")
			return
		}
		e := v.Elem()
		d.emit(path, "iface<"+e.Type().String()+">")
		d.walk(path+"!", e, depth+1)

	case reflect.Struct:
		if !v.CanAddr() {
			tmp := reflect.New(t).Elem()
			tmp.Set(v)
			v = tmp
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if d.opt.SkipFields[t.String()+"."+f.Name] {
				d.emit(path+"."+f.Name, "<skip field>")
				continue
			}
			fv := v.Field(i)
			if f.PkgPath != "" {
				fv = expose(fv)
			}
			d.walk(path+"."+f.Name, fv, depth+1)
		}

	case reflect.Map:
		if v.IsNil() {
			if d.opt.StrictNil {
				d.emit(path, "nil-map")
			} else {
				d.emit(path, "map(len=0)")
			}
			return
		}
		keys := v.MapKeys()
		reps := make([]string, len(keys))
		order := make([]int, len(keys))
		for i, k := range keys {
			reps[i] = keyRepr(k, d.opt)
			order[i] = i
		}
		sort.Slice(order, func(a, b int) bool { return reps[order[a]] < reps[order[b]] })
		d.emit(path, "map(len="+strconv.Itoa(len(keys))+")")
		for _, i := range order {
			d.walk(path+"["+reps[i]+"]", v.MapIndex(keys[i]), depth+1)
		}

	case reflect.Slice:
		if v.IsNil() {
			if d.opt.StrictNil {
				d.emit(path, "nil-slice")
			} else if t.Elem().Kind() == reflect.Uint8 {
				d.emit(path, "bytes(0):")
			} else {
				d.emit(path, "slice(len=0)")
			}
			return
		}
		if t.Elem().Kind() == reflect.Uint8 {
			d.emit(path, "bytes("+strconv.Itoa(v.Len())+"):"+byteString(v))
			return
		}
		d.emit(path, "slice(len="+strconv.Itoa(v.Len())+")")
		for i := 0; i < v.Len(); i++ {
			d.walk(path+"["+strconv.Itoa(i)+"]", v.Index(i), depth+1)
		}

	case reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			d.emit(path, "bytes("+strconv.Itoa(v.Len())+"):"+byteString(v))
			return
		}
		for i := 0; i < v.Len(); i++ {
			d.walk(path+"["+strconv.Itoa(i)+"]", v.Index(i), depth+1)
		}

	case reflect.Func:
		if v.IsNil() {
			d.emit(path, "func:nil")
		} else {
			d.emit(path, "func:set")
		}

	case reflect.Chan:
		if v.IsNil() {
			d.emit(path, "chan:nil")
		} else {
			d.emit(path, "chan(len="+strconv.Itoa(v.Len())+")")
		}

	case reflect.UnsafePointer:
		d.emit(path, "unsafeptr")

	case reflect.String:
		d.emit(path, strconv.Quote(v.String()))

	case reflect.Bool:
		d.emit(path, strconv.FormatBool(v.Bool()))

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		d.emit(path, strconv.FormatInt(v.Int(), 10))

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		d.emit(path, strconv.FormatUint(v.Uint(), 10))

	case reflect.Float32, reflect.Float64:
		// Hex float: exact, so a 1-ulp vote-rights drift cannot round away.
		d.emit(path, strconv.FormatFloat(v.Float(), 'x', -1, 64))

	case reflect.Complex64, reflect.Complex128:
		d.emit(path, fmt.Sprint(v.Complex()))

	default:
		d.emit(path, "<kind "+v.Kind().String()+">")
	}
}

// keyRepr renders a map key compactly and canonically for sorting.
func keyRepr(k reflect.Value, opt Options) string {
	opt.Identity = false
	sub := &dumper{opt: opt, ids: map[ptrKey]int{}, onPath: map[ptrKey]bool{}, budget: 100000}
	sub.walk("", k, 0)
	parts := make([]string, 0, len(sub.lines))
	for _, ln := range sub.lines {
		parts = append(parts, strings.TrimPrefix(ln, " = "))
	}
	return strings.Join(parts, ";")
}

// Diff compares two dumps by path and returns "" when they are identical.
// Up to max differences are rendered.
func Diff(a, b string, max int) string {
	ma, oa := parse(a)
	mb, _ := parse(b)

	var out []string
	n := 0
	for _, p := range oa {
		va := ma[p]
		vb, ok := mb[p]
		if !ok {
			n++
			if len(out) < max {
				out = append(out, "  only-in-A  "+p+" = "+va)
			}
			continue
		}
		if va != vb {
			n++
			if len(out) < max {
				out = append(out, "  differs    "+p+"\n      A: "+va+"\n      B: "+vb)
			}
		}
	}
	bkeys := make([]string, 0, len(mb))
	for p := range mb {
		if _, ok := ma[p]; !ok {
			bkeys = append(bkeys, p)
		}
	}
	sort.Strings(bkeys)
	for _, p := range bkeys {
		n++
		if len(out) < max {
			out = append(out, "  only-in-B  "+p+" = "+mb[p])
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d difference(s):\n%s", n, strings.Join(out, "\n"))
}

func parse(s string) (map[string]string, []string) {
	m := make(map[string]string)
	var order []string
	for _, ln := range strings.Split(s, "\n") {
		i := strings.Index(ln, " = ")
		if i < 0 {
			continue
		}
		p, v := ln[:i], ln[i+3:]
		if _, dup := m[p]; dup {
			// Paths are structural and unique; a duplicate would silently mask a
			// difference, so make it loud instead.
			p = p + "#dup"
		}
		m[p] = v
		order = append(order, p)
	}
	return m, order
}
