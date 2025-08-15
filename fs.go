// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"errors"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
)

// Domain separation constants for different protocols
const (
	DOMAIN_CIRCUIT = "EMZA-BP++-Circuit-v1"
	DOMAIN_RANGE   = "EMZA-BP++-Range-v1"
	DOMAIN_WNLA    = "EMZA-BP++-WNLA-v1"
)

type FiatShamirEngine interface {
	AddPoint(*bn256.G1) error
	AddNumber(*big.Int) error
	AddDomain(domain string) error
	AddBytes([]byte) error
	GetChallenge() *big.Int
}

type KeccakFS struct {
	state   KeccakState
	counter int
}

func NewKeccakFS() FiatShamirEngine {
	return &KeccakFS{state: NewKeccakState()}
}

// AddDomain adds a domain separation tag to prevent cross-protocol attacks
func (k *KeccakFS) AddDomain(domain string) error {
	if domain == "" {
		return errors.New("domain cannot be empty")
	}

	// Write domain tag followed by separator
	if _, err := k.state.Write([]byte(domain)); err != nil {
		return fmt.Errorf("failed to write domain tag: %w", err)
	}
	if _, err := k.state.Write([]byte{0x00}); err != nil {
		return fmt.Errorf("failed to write domain separator: %w", err)
	}

	return nil
}

func (k *KeccakFS) AddPoint(p *bn256.G1) error {
	if p == nil {
		return errors.New("point cannot be nil")
	}

	if _, err := k.state.Write(p.Marshal()); err != nil {
		return fmt.Errorf("failed to write point to transcript: %w", err)
	}
	return nil
}

func (k *KeccakFS) AddNumber(v *big.Int) error {
	if v == nil {
		return errors.New("number cannot be nil")
	}

	if _, err := k.state.Write(scalarTo32Byte(v)); err != nil {
		return fmt.Errorf("failed to write number to transcript: %w", err)
	}
	return nil
}

func (k *KeccakFS) AddBytes(data []byte) error {
	if data == nil {
		return errors.New("data cannot be nil")
	}

	if _, err := k.state.Write(data); err != nil {
		return fmt.Errorf("failed to write bytes to transcript: %w", err)
	}
	return nil
}

func (k *KeccakFS) GetChallenge() *big.Int {
	k.counter++
	// Note: This AddNumber call needs error handling in calling code
	k.AddNumber(bint(k.counter))
	return new(big.Int).Mod(new(big.Int).SetBytes(k.state.Sum(nil)), bn256.Order)
}

func scalarTo32Byte(s *big.Int) []byte {
	arr := s.Bytes()
	if len(arr) >= 32 {
		return arr[:32]
	}

	res := make([]byte, 32-len(arr))
	return append(res, arr...)
}
