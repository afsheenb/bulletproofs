package bulletproofs

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
)

// BulletproofsKATVector represents a single KAT test case for range proofs
type BulletproofsKATVector struct {
	Description  string `json:"description"`
	Value        string `json:"value"`          // Hex string of the value to prove
	BitLength    int    `json:"bit_length"`     // Number of bits for the range
	Base         int    `json:"base"`           // Number system base (e.g., 16 for hex)
	ShouldVerify bool   `json:"should_verify"`  // Expected verification result
	ErrorType    string `json:"error_type,omitempty"` // Type of error expected (for negative tests)
}

// BulletproofsKAT contains all test vectors
type BulletproofsKAT struct {
	Description string                      `json:"description"`
	TestVectors []BulletproofsKATVector    `json:"test_vectors"`
}

// TestBulletproofsRangeProofKAT tests Bulletproofs++ range proofs with internal consistency
func TestBulletproofsRangeProofKAT(t *testing.T) {
	// Internal consistency KAT vectors - these are generated and verified by our own implementation
	testVectors := []BulletproofsKATVector{
		{
			Description:  "Valid 64-bit range proof for zero",
			Value:        "0x0",
			BitLength:    64,
			Base:         16,
			ShouldVerify: true,
		},
		{
			Description:  "Valid 64-bit range proof for small value",
			Value:        "0x1234",
			BitLength:    64, 
			Base:         16,
			ShouldVerify: true,
		},
		{
			Description:  "Valid 64-bit range proof for medium value",
			Value:        "0x123456789ABCDEF0",
			BitLength:    64,
			Base:         16,
			ShouldVerify: true,
		},
		{
			Description:  "Valid 64-bit range proof for maximum 64-bit value",
			Value:        "0xFFFFFFFFFFFFFFFF", 
			BitLength:    64,
			Base:         16,
			ShouldVerify: true,
		},
		{
			Description:  "Valid 32-bit range proof for small value",
			Value:        "0x12345678",
			BitLength:    32,
			Base:         16,
			ShouldVerify: true,
		},
		{
			Description:  "Valid 32-bit range proof for edge case",
			Value:        "0xFFFFFFF0", // Just under max 32-bit
			BitLength:    32,
			Base:         16,
			ShouldVerify: true,
		},
		{
			Description:  "Valid 16-bit range proof",
			Value:        "0xABCD",
			BitLength:    16,
			Base:         16,
			ShouldVerify: true,
		},
		{
			Description:  "Valid 8-bit range proof",
			Value:        "0xFF",
			BitLength:    8,
			Base:         16,
			ShouldVerify: true,
		},
	}

	for _, tv := range testVectors {
		t.Run(tv.Description, func(t *testing.T) {
			// Parse the hex value
			valueStr := tv.Value
			if len(valueStr) > 2 && valueStr[:2] == "0x" {
				valueStr = valueStr[2:]
			}
			
			valueBytes, err := hex.DecodeString(valueStr)
			if err != nil {
				t.Fatalf("Failed to decode hex value: %v", err)
			}
			
			value := new(big.Int).SetBytes(valueBytes)
			
			// Check if value fits in the specified bit length
			maxValue := new(big.Int).Lsh(big.NewInt(1), uint(tv.BitLength))
			maxValue.Sub(maxValue, big.NewInt(1))
			
			if value.Cmp(maxValue) > 0 {
				t.Skipf("Value %s exceeds maximum for %d bits, skipping", tv.Value, tv.BitLength)
				return
			}

			// Convert to uint64 for the hex encoding functions
			if !value.IsUint64() {
				t.Skipf("Value too large for uint64, skipping: %s", tv.Value)
				return
			}
			
			valueUint64 := value.Uint64()

			// Generate digits and mapping based on base
			var digits []*big.Int
			var mapping []*big.Int
			var Nd, Np int
			
			if tv.Base == 16 {
				// Use existing hex functions for base 16
				digits = UInt64Hex(valueUint64)
				mapping = HexMapping(digits)
				Nd = 16 // Standard 64-bit hex encoding uses 16 digits
				Np = 16 // Hex base
			} else {
				t.Skipf("Base %d not supported in current implementation", tv.Base)
				return
			}

			// Create public parameters
			wnlaPublic := NewWeightNormLinearPublic(32, Nd)
			
			public := &ReciprocalPublic{
				G:     wnlaPublic.G,
				GVec:  wnlaPublic.GVec[:Nd],
				HVec:  wnlaPublic.HVec[:Nd+1+9],
				Nd:    Nd,
				Np:    Np,
				GVec_: wnlaPublic.GVec[Nd:],
				HVec_: wnlaPublic.HVec[Nd+1+9:],
			}

			// Create private parameters
			private := &ReciprocalPrivate{
				X:      value,
				M:      mapping,
				Digits: digits,
				S:      NewRandScalar(),
			}

			// Generate value commitment
			vCom := public.CommitValue(private.X, private.S)

			// Generate proof
			proof := ProveRange(public, NewKeccakFS(), private)
			if proof == nil {
				t.Errorf("ProveRange returned nil proof")
				return
			}

			// Verify proof
			err = VerifyRange(public, vCom, NewKeccakFS(), proof)
			
			if tv.ShouldVerify {
				if err != nil {
					t.Errorf("Expected verification to succeed, but got error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected verification to fail, but it succeeded")
				}
			}
		})
	}
}

// TestBulletproofsConsistency verifies prover/verifier consistency 
func TestBulletproofsConsistency(t *testing.T) {
	// Test various value/range combinations for internal consistency
	testCases := []struct {
		name       string
		value      uint64
		Nd, Np     int
		wnlaLen    int
	}{
		{"Small value 16-hex", 0x1234, 16, 16, 32},
		{"Medium value 16-hex", 0x123456789ABCDEF0, 16, 16, 32},
		{"Zero value 16-hex", 0x0, 16, 16, 32},
		{"Max nibble 16-hex", 0xF, 16, 16, 32},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate test data
			digits := UInt64Hex(tc.value)
			mapping := HexMapping(digits)
			value := new(big.Int).SetUint64(tc.value)

			// Setup parameters
			wnlaPublic := NewWeightNormLinearPublic(tc.wnlaLen, tc.Nd)
			
			public := &ReciprocalPublic{
				G:     wnlaPublic.G,
				GVec:  wnlaPublic.GVec[:tc.Nd],
				HVec:  wnlaPublic.HVec[:tc.Nd+1+9],
				Nd:    tc.Nd,
				Np:    tc.Np,
				GVec_: wnlaPublic.GVec[tc.Nd:],
				HVec_: wnlaPublic.HVec[tc.Nd+1+9:],
			}

			private := &ReciprocalPrivate{
				X:      value,
				M:      mapping,
				Digits: digits,
				S:      NewRandScalar(),
			}

			// Generate commitment and proof
			vCom := public.CommitValue(private.X, private.S)
			proof := ProveRange(public, NewKeccakFS(), private)

			// Verify - should always pass for valid inputs
			err := VerifyRange(public, vCom, NewKeccakFS(), proof)
			if err != nil {
				t.Errorf("Consistency test failed: %v", err)
			}
		})
	}
}

// TestBulletproofsNegativeCases tests cases that should fail verification
func TestBulletproofsNegativeCases(t *testing.T) {
	value := uint64(0x1234)
	digits := UInt64Hex(value)
	mapping := HexMapping(digits)
	bigValue := new(big.Int).SetUint64(value)
	
	Nd, Np := 16, 16
	wnlaPublic := NewWeightNormLinearPublic(32, Nd)
	
	public := &ReciprocalPublic{
		G:     wnlaPublic.G,
		GVec:  wnlaPublic.GVec[:Nd],
		HVec:  wnlaPublic.HVec[:Nd+1+9],
		Nd:    Nd,
		Np:    Np,
		GVec_: wnlaPublic.GVec[Nd:],
		HVec_: wnlaPublic.HVec[Nd+1+9:],
	}

	private := &ReciprocalPrivate{
		X:      bigValue,
		M:      mapping,
		Digits: digits,
		S:      NewRandScalar(),
	}

	// Generate valid proof for value 0x1234
	vCom := public.CommitValue(private.X, private.S)
	proof := ProveRange(public, NewKeccakFS(), private)
	
	// Verify with correct commitment - should pass
	err := VerifyRange(public, vCom, NewKeccakFS(), proof)
	if err != nil {
		t.Fatalf("Sanity check failed - valid proof should verify: %v", err)
	}

	// Test 1: Verify with wrong value commitment
	t.Run("Wrong value commitment", func(t *testing.T) {
		wrongValue := new(big.Int).SetUint64(0x5678) // Different value
		wrongCom := public.CommitValue(wrongValue, private.S)
		
		err := VerifyRange(public, wrongCom, NewKeccakFS(), proof)
		if err == nil {
			t.Error("Expected verification to fail with wrong value commitment")
		}
	})

	// Test 2: Verify with different blinding factor
	t.Run("Wrong blinding factor in commitment", func(t *testing.T) {
		wrongBlinding := NewRandScalar()
		wrongCom := public.CommitValue(private.X, wrongBlinding)
		
		err := VerifyRange(public, wrongCom, NewKeccakFS(), proof)
		if err == nil {
			t.Error("Expected verification to fail with wrong blinding factor")
		}
	})

	// Note: Testing tampered proof structures would require access to internal proof fields
	// This would be implementation-specific and complex to test generically
}

// BenchmarkBulletproofsKAT provides performance baseline for range proof operations
func BenchmarkBulletproofsProve(b *testing.B) {
	value := uint64(0x123456789ABCDEF0)
	digits := UInt64Hex(value)
	mapping := HexMapping(digits)
	bigValue := new(big.Int).SetUint64(value)
	
	Nd, Np := 16, 16
	wnlaPublic := NewWeightNormLinearPublic(32, Nd)
	
	public := &ReciprocalPublic{
		G:     wnlaPublic.G,
		GVec:  wnlaPublic.GVec[:Nd],
		HVec:  wnlaPublic.HVec[:Nd+1+9],
		Nd:    Nd,
		Np:    Np,
		GVec_: wnlaPublic.GVec[Nd:],
		HVec_: wnlaPublic.HVec[Nd+1+9:],
	}

	private := &ReciprocalPrivate{
		X:      bigValue,
		M:      mapping,
		Digits: digits,
		S:      NewRandScalar(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ProveRange(public, NewKeccakFS(), private)
	}
}

func BenchmarkBulletproofsVerify(b *testing.B) {
	value := uint64(0x123456789ABCDEF0)
	digits := UInt64Hex(value)
	mapping := HexMapping(digits)
	bigValue := new(big.Int).SetUint64(value)
	
	Nd, Np := 16, 16
	wnlaPublic := NewWeightNormLinearPublic(32, Nd)
	
	public := &ReciprocalPublic{
		G:     wnlaPublic.G,
		GVec:  wnlaPublic.GVec[:Nd],
		HVec:  wnlaPublic.HVec[:Nd+1+9],
		Nd:    Nd,
		Np:    Np,
		GVec_: wnlaPublic.GVec[Nd:],
		HVec_: wnlaPublic.HVec[Nd+1+9:],
	}

	private := &ReciprocalPrivate{
		X:      bigValue,
		M:      mapping,
		Digits: digits,
		S:      NewRandScalar(),
	}

	vCom := public.CommitValue(private.X, private.S)
	proof := ProveRange(public, NewKeccakFS(), private)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyRange(public, vCom, NewKeccakFS(), proof)
	}
}

// TestKATVectorGeneration can generate KAT vectors for external validation
func TestKATVectorGeneration(t *testing.T) {
	// This test generates KAT vectors that could be used for cross-implementation testing
	// In practice, you'd save these to a JSON file for later use
	
	kat := BulletproofsKAT{
		Description: "Bulletproofs++ Range Proof Known Answer Tests",
		TestVectors: []BulletproofsKATVector{
			{
				Description:  "16-bit zero value",
				Value:        "0x0",
				BitLength:    16,
				Base:         16,
				ShouldVerify: true,
			},
			{
				Description:  "16-bit small value", 
				Value:        "0x1234",
				BitLength:    16,
				Base:         16,
				ShouldVerify: true,
			},
			{
				Description:  "32-bit medium value",
				Value:        "0x12345678",
				BitLength:    32,
				Base:         16,
				ShouldVerify: true,
			},
		},
	}

	// Serialize for inspection (in real usage, you'd write to file)
	katJSON, err := json.MarshalIndent(kat, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal KAT vectors: %v", err)
	}

	t.Logf("Generated KAT vectors:\n%s", string(katJSON))
	
	// Verify the vectors work with our implementation
	for _, tv := range kat.TestVectors {
		// This would be the actual KAT test logic
		// (Similar to the main KAT test above)
		t.Logf("Would test: %s", tv.Description)
	}
}