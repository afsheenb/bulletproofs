// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
)

// CommitWNLA creates a commitment for vectors n, l based on public parameters p.
// Commit(l, n) = v*G + <l, H> + <n, G>
// where v = <c, l> + |n^2|_mu
func (p *WeightNormLinearPublic) CommitWNLA(l []*big.Int, n []*big.Int) *bn256.G1 {
	v_ := add(vectorMul(p.C, l), weightVectorMul(n, n, p.Mu))
	C := new(bn256.G1).ScalarMult(p.G, v_)
	C.Add(C, vectorPointScalarMul(p.HVec, l))
	C.Add(C, vectorPointScalarMul(p.GVec, n))
	return C
}

// VerifyWNLA verifies the weight norm linear argument proof. If err is nil then proof is valid.
// Use empty FiatShamirEngine for call. Also, use the same commitment that has been used during proving.
func VerifyWNLA(public *WeightNormLinearPublic, proof *WeightNormLinearArgumentProof, Com *bn256.G1, fs FiatShamirEngine) error {
	if len(proof.X) != len(proof.R) {
		return errors.New("invalid length for R and X vectors: should be equal")
	}

	if len(proof.X) == 0 {
		// Base case: verify final commitment matches the reduced parameters
		commitment := public.CommitWNLA(proof.L, proof.N)
		if commitment == nil {
			return errors.New("commitment calculation failed - possible overflow")
		}

		if !bytes.Equal(commitment.Marshal(), Com.Marshal()) {
			return fmt.Errorf("failed to verify proof: final commitment mismatch")
		}

		return nil
	}

	// Simple Fiat-Shamir transcript matching original implementation
	if err := fs.AddPoint(Com); err != nil {
		return fmt.Errorf("failed to add commitment to transcript: %w", err)
	}
	if err := fs.AddPoint(proof.X[0]); err != nil {
		return fmt.Errorf("failed to add proof X to transcript: %w", err)
	}
	if err := fs.AddPoint(proof.R[0]); err != nil {
		return fmt.Errorf("failed to add proof R to transcript: %w", err)
	}
	if err := fs.AddNumber(bint(len(public.HVec))); err != nil {
		return fmt.Errorf("failed to add HVec length to transcript: %w", err)
	}
	if err := fs.AddNumber(bint(len(public.GVec))); err != nil {
		return fmt.Errorf("failed to add GVec length to transcript: %w", err)
	}

	// Challenge using Fiat-Shamir heuristic
	y := fs.GetChallenge()

	c0, c1 := reduceVector(public.C)
	G0, G1 := reducePoints(public.GVec)
	H0, H1 := reducePoints(public.HVec)

	// Both calculates new vector points and new commitment
	H_ := vectorPointsAdd(H0, vectorPointMulOnScalar(H1, y))
	G_ := vectorPointsAdd(vectorPointMulOnScalar(G0, public.Ro), vectorPointMulOnScalar(G1, y))
	c_ := vectorAdd(c0, vectorMulOnScalar(c1, y))

	// CRITICAL FIX: Update commitment algebraically
	// Com' = Com + X*y + R*(y²-1)
	Com_ := new(bn256.G1).Set(Com)
	Com_.Add(Com_, new(bn256.G1).ScalarMult(proof.X[0], y))
	Com_.Add(Com_, new(bn256.G1).ScalarMult(proof.R[0], sub(mul(y, y), bint(1))))

	// Recursive run
	return VerifyWNLA(
		&WeightNormLinearPublic{
			G:    public.G,
			GVec: G_,
			HVec: H_,
			C:    c_,
			Ro:   public.Mu,
			Mu:   mul(public.Mu, public.Mu),
		},
		&WeightNormLinearArgumentProof{
			R: proof.R[1:],
			X: proof.X[1:],
			L: proof.L,
			N: proof.N,
		},
		Com_,
		fs,
	)
}

// ProveWNLA generates zero knowledge proof of knowledge of two vectors l and n that
// satisfies the commitment C (see WeightNormLinearPublic.Commit() function).
// Use empty FiatShamirEngine for call.
func ProveWNLA(public *WeightNormLinearPublic, Com *bn256.G1, fs FiatShamirEngine, l, n []*big.Int) *WeightNormLinearArgumentProof {
	// Pass original commitment unchanged through recursion
	return proveWNLARecursive(public, Com, fs, l, n)
}

// proveWNLARecursive handles the recursive proving logic without domain separation
func proveWNLARecursive(public *WeightNormLinearPublic, Com *bn256.G1, fs FiatShamirEngine, l, n []*big.Int) *WeightNormLinearArgumentProof {
	if len(l)+len(n) < 6 {

		// Prover sends l, n to Verifier
		return &WeightNormLinearArgumentProof{
			R: make([]*bn256.G1, 0),
			X: make([]*bn256.G1, 0),
			L: l,
			N: n,
		}
	}

	roinv := inv(public.Ro)

	// Prover calculates new reduced values, vx and vr and sends X, R to verifier
	c0, c1 := reduceVector(public.C)
	l0, l1 := reduceVector(l)
	n0, n1 := reduceVector(n)
	G0, G1 := reducePoints(public.GVec)
	H0, H1 := reducePoints(public.HVec)

	mu2 := mul(public.Mu, public.Mu)

	vx := add(
		mul(weightVectorMul(n0, n1, mu2), mul(bint(2), roinv)),
		add(vectorMul(c0, l1), vectorMul(c1, l0)),
	)

	vr := add(weightVectorMul(n1, n1, mu2), vectorMul(c1, l1))

	X := new(bn256.G1).ScalarMult(public.G, vx)
	X.Add(X, vectorPointScalarMul(H0, l1))
	X.Add(X, vectorPointScalarMul(H1, l0))
	X.Add(X, vectorPointScalarMul(G0, vectorMulOnScalar(n1, public.Ro)))
	X.Add(X, vectorPointScalarMul(G1, vectorMulOnScalar(n0, roinv)))

	R := new(bn256.G1).ScalarMult(public.G, vr)
	R.Add(R, vectorPointScalarMul(H1, l1))
	R.Add(R, vectorPointScalarMul(G1, n1))

	// Simple Fiat-Shamir transcript matching original implementation
	_ = fs.AddPoint(Com)
	_ = fs.AddPoint(X)
	_ = fs.AddPoint(R)
	_ = fs.AddNumber(bint(len(public.HVec)))
	_ = fs.AddNumber(bint(len(public.GVec)))

	// Challenge using Fiat-Shamir heuristic
	y := fs.GetChallenge()

	// Both calculates new vector points and new commitment
	H_ := vectorPointsAdd(H0, vectorPointMulOnScalar(H1, y))
	G_ := vectorPointsAdd(vectorPointMulOnScalar(G0, public.Ro), vectorPointMulOnScalar(G1, y))
	c_ := vectorAdd(c0, vectorMulOnScalar(c1, y))

	// Prover calculates new reduced vectors
	l_ := vectorAdd(l0, vectorMulOnScalar(l1, y))
	n_ := vectorAdd(vectorMulOnScalar(n0, roinv), vectorMulOnScalar(n1, y))

	public_ := &WeightNormLinearPublic{
		G:    public.G,
		GVec: G_,
		HVec: H_,
		C:    c_,
		Ro:   public.Mu,
		Mu:   mu2,
	}

	// Compute fresh commitment with transformed parameters (correct approach)
	commitment := public_.CommitWNLA(l_, n_)
	if commitment == nil {
		// If commitment fails, return an empty proof indicating failure
		return &WeightNormLinearArgumentProof{
			R: []*bn256.G1{},
			X: []*bn256.G1{},
			L: l_,
			N: n_,
		}
	}

	res := proveWNLARecursive(
		public_,
		commitment,
		fs,
		l_,
		n_,
	)

	return &WeightNormLinearArgumentProof{
		R: append([]*bn256.G1{R}, res.R...),
		X: append([]*bn256.G1{X}, res.X...),
		L: res.L,
		N: res.N,
	}
}

func reduceVector(v []*big.Int) ([]*big.Int, []*big.Int) {
	res0 := make([]*big.Int, 0, len(v)/2)
	res1 := make([]*big.Int, 0, len(v)/2)

	for i := range v {
		if i%2 == 0 {
			res0 = append(res0, v[i])
		} else {
			res1 = append(res1, v[i])
		}
	}

	return res0, res1
}

func reducePoints(v []*bn256.G1) ([]*bn256.G1, []*bn256.G1) {
	res0 := make([]*bn256.G1, 0, len(v)/2)
	res1 := make([]*bn256.G1, 0, len(v)/2)

	for i := range v {
		if i%2 == 0 {
			res0 = append(res0, v[i])
		} else {
			res1 = append(res1, v[i])
		}
	}

	return res0, res1
}
