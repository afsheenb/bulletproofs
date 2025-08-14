// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"github.com/cloudflare/bn256"
	"math/big"
	"testing"
)

func TestKeccakFS(t *testing.T) {
	fs := NewKeccakFS()
	fs.AddNumber(bint(1))
	fs.AddNumber(bint(2))

	c1 := fs.GetChallenge()

	c2 := new(big.Int).Mod(
		new(big.Int).SetBytes(
			Keccak256(
				scalarTo32Byte(bint(1)),
				scalarTo32Byte(bint(2)),
				scalarTo32Byte(bint(1)), // counter from GetChallenge
			),
		),
		bn256.Order,
	)

	if c1.Cmp(c2) != 0 {
		panic("test failed")
	}

	fs.AddNumber(bint(3))
	c3 := fs.GetChallenge()

	c4 := new(big.Int).Mod(
		new(big.Int).SetBytes(
			Keccak256(
				scalarTo32Byte(bint(1)),
				scalarTo32Byte(bint(2)),
				scalarTo32Byte(bint(1)), // counter from first GetChallenge
				scalarTo32Byte(bint(3)),
				scalarTo32Byte(bint(2)), // counter from second GetChallenge
			),
		),
		bn256.Order,
	)

	if c3.Cmp(c4) != 0 {
		panic("test failed")
	}
}
