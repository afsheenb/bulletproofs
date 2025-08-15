// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
)

// NewRandPoint creates a new random point, panicking if random generation fails
// This is for internal use in setup/testing where crypto failure should be fatal
func NewRandPoint() *bn256.G1 {
	p, err := SecureRandPoint()
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random point: %v", err))
	}
	return p
}

// NewRandScalar creates a new random scalar, panicking if random generation fails
// This is for internal use in setup/testing where crypto failure should be fatal
func NewRandScalar() *big.Int {
	s, err := SecureRandScalar()
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random scalar: %v", err))
	}
	return s
}

// SecureRandScalar generates a cryptographically secure random scalar with entropy validation
// Uses rejection sampling for unbiased field element generation
func SecureRandScalar() (*big.Int, error) {
	// Use 64 bytes of entropy for extra security margin
	entropy := make([]byte, 64)
	if _, err := rand.Read(entropy); err != nil {
		return nil, fmt.Errorf("insufficient entropy for scalar generation: %w", err)
	}

	// Validate entropy quality - ensure not all zeros
	allZero := true
	for _, b := range entropy {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("entropy validation failed: all zero bytes detected")
	}

	// Use hash-based approach with rejection sampling for unbiased generation
	return hashToScalarWithRejection(entropy)
}

// SecureRandPoint generates a cryptographically secure random group element with validation
func SecureRandPoint() (*bn256.G1, error) {
	// Generate secure scalar first
	scalar, err := SecureRandScalar()
	if err != nil {
		return nil, fmt.Errorf("failed to generate scalar for point: %w", err)
	}

	// Use scalar multiplication with generator point for secure point generation
	point := new(bn256.G1).ScalarBaseMult(scalar)

	// Validate the point is not identity by checking if it marshals to zero bytes
	marshaled := point.Marshal()
	if len(marshaled) == 0 {
		return nil, errors.New("generated point validation failed: marshaling produced empty result")
	}

	// Additional check - see if all bytes are zero (identity element)
	allZero := true
	for _, b := range marshaled {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("generated point validation failed: identity element")
	}

	return point, nil
}

// hashToScalarWithRejection uses rejection sampling to generate unbiased field elements
func hashToScalarWithRejection(entropy []byte) (*big.Int, error) {
	// Maximum attempts to prevent infinite loops
	const maxAttempts = 100

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Hash entropy with attempt counter for different values
		hasher := sha256.New()
		hasher.Write(entropy)
		hasher.Write([]byte{byte(attempt)})
		hash := hasher.Sum(nil)

		// Convert hash to big integer
		candidate := new(big.Int).SetBytes(hash)

		// Rejection sampling: accept if candidate < bn256.Order
		if candidate.Cmp(bn256.Order) < 0 {
			return candidate, nil
		}
	}

	return nil, fmt.Errorf("rejection sampling failed after %d attempts", maxAttempts)
}

// ValidateEntropy performs basic entropy quality checks
func ValidateEntropy(data []byte) error {
	if len(data) < 32 {
		return errors.New("insufficient entropy: minimum 32 bytes required")
	}

	// Check for all zeros
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return errors.New("entropy validation failed: all zero bytes")
	}

	// Check for all same value (basic pattern detection)
	firstByte := data[0]
	allSame := true
	for _, b := range data[1:] {
		if b != firstByte {
			allSame = false
			break
		}
	}
	if allSame {
		return errors.New("entropy validation failed: all bytes have same value")
	}

	return nil
}
