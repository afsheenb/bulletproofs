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
	err1 := fs.AddNumber(bint(1))
	if err1 != nil {
		t.Fatalf("AddNumber failed: %v", err1)
	}

	err2 := fs.AddNumber(bint(2))
	if err2 != nil {
		t.Fatalf("AddNumber failed: %v", err2)
	}

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
		t.Error("Challenge generation mismatch")
	}

	err3 := fs.AddNumber(bint(3))
	if err3 != nil {
		t.Fatalf("AddNumber failed: %v", err3)
	}

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
		t.Error("Sequential challenge generation mismatch")
	}
}

// TestDomainSeparation tests the new domain separation security feature
func TestDomainSeparation(t *testing.T) {
	// Test all domain constants are different
	domains := []string{DOMAIN_CIRCUIT, DOMAIN_RANGE, DOMAIN_WNLA}

	for i := 0; i < len(domains); i++ {
		for j := i + 1; j < len(domains); j++ {
			if domains[i] == domains[j] {
				t.Errorf("Domain collision: %s == %s", domains[i], domains[j])
			}
		}
	}

	// Test domain separation affects challenge generation
	fs1 := NewKeccakFS()
	fs2 := NewKeccakFS()

	// Same data, different domains
	testNum := bint(12345)

	err1 := fs1.AddDomain(DOMAIN_CIRCUIT)
	if err1 != nil {
		t.Fatalf("AddDomain failed: %v", err1)
	}

	err2 := fs1.AddNumber(testNum)
	if err2 != nil {
		t.Fatalf("AddNumber failed: %v", err2)
	}

	err3 := fs2.AddDomain(DOMAIN_RANGE)
	if err3 != nil {
		t.Fatalf("AddDomain failed: %v", err3)
	}

	err4 := fs2.AddNumber(testNum)
	if err4 != nil {
		t.Fatalf("AddNumber failed: %v", err4)
	}

	challenge1 := fs1.GetChallenge()
	challenge2 := fs2.GetChallenge()

	if challenge1.Cmp(challenge2) == 0 {
		t.Error("Domain separation failed: same challenge for different domains")
	}
}

// TestErrorHandling tests the new error handling instead of panics
func TestErrorHandling(t *testing.T) {
	fs := NewKeccakFS()

	// Test AddDomain with empty string
	err := fs.AddDomain("")
	if err == nil {
		t.Error("Should reject empty domain string")
	}

	// Test AddNumber with nil
	err = fs.AddNumber(nil)
	if err == nil {
		t.Error("Should reject nil number")
	}

	// Test AddPoint with nil
	err = fs.AddPoint(nil)
	if err == nil {
		t.Error("Should reject nil point")
	}

	// Test valid operations work
	err = fs.AddDomain(DOMAIN_CIRCUIT)
	if err != nil {
		t.Errorf("Valid AddDomain should not fail: %v", err)
	}

	err = fs.AddNumber(bint(123))
	if err != nil {
		t.Errorf("Valid AddNumber should not fail: %v", err)
	}

	// Test AddPoint with a valid point - create point from scalar multiplication
	testPoint := new(bn256.G1).ScalarBaseMult(bint(42))
	err = fs.AddPoint(testPoint)
	if err != nil {
		t.Errorf("Valid AddPoint should not fail: %v", err)
	}
}
