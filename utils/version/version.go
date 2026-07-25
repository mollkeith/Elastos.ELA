// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package version holds the single authoritative version string for every
// binary built from this source tree.
//
// Before this package the tree carried NO version string at all: the Makefile
// injected `git describe --abbrev=4 --dirty --always --tags` into main.Version
// with -ldflags, so what a binary reported was a property of the BUILDER's
// working copy (which tags it happened to have fetched, whether it was dirty)
// rather than of the source. A build from an exported tarball reported the
// empty string, and two builders of the same commit could -- and on this tree
// did -- produce different bytes for the same source. A consensus binary that a
// fleet must run in lockstep has to be identifiable from the source alone, so
// the release version is a compiled-in constant here and the release build no
// longer stamps it.
package version

// Version is the version of this source tree, reported by `ela --version`,
// `ela-cli --version`, `ela-dns -v`, the node startup banner, the P2P user
// agent ("ela-" + Version) and the getnodestate/getnetworkinfo "compile" RPC
// field.
//
// Keep it short: the P2P version message caps its whole payload at 82 bytes
// (p2p/msg/version.go MaxLength), of which 35 are fixed fields, so the
// advertised "ela-"+Version string must stay well under 46 characters.
//
// Bump this constant -- and only this constant -- when cutting a release.
const Version = "v1.0.0"
