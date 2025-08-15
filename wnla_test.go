// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"github.com/davecgh/go-spew/spew"
	"math/big"
	"testing"
)

func TestWNLA(t *testing.T) {
	// Use smaller dimensions to reduce chance of overflow with large random parameters
	public := NewWeightNormLinearPublic(4, 2)
	spew.Dump(public)

	// Use small values to avoid triggering overflow protection
	l := []*big.Int{bint(1), bint(2), bint(3), bint(4)}
	n := []*big.Int{bint(5), bint(6)}

	commitment := public.CommitWNLA(l, n)
	if commitment == nil {
		t.Fatal("CommitWNLA returned nil - possible overflow protection triggered")
	}

	proof := ProveWNLA(public, commitment, NewKeccakFS(), l, n)
	spew.Dump(proof)

	if err := VerifyWNLA(public, proof, commitment, NewKeccakFS()); err != nil {
		t.Fatalf("WNLA verification failed: %v", err)
	}
}

