/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

package ont

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"math/rand"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/ontio/ontology-crypto/sm3"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ripemd160"
)

// GetNonce returns random nonce
func GetNonce() uint64 {
	// Fixme replace with the real random number generator
	nonce := uint64(rand.Uint32())<<32 + uint64(rand.Uint32())
	return nonce
}

// ToHexString convert []byte to hex string
func ToHexString(data []byte) string {
	return hex.EncodeToString(data)
}

// HexToBytes convert hex string to []byte
func HexToBytes(value string) ([]byte, error) {
	return hex.DecodeString(value)
}

func ToArrayReverse(arr []byte) []byte {
	l := len(arr)
	x := make([]byte, 0)
	for i := l - 1; i >= 0; i-- {
		x = append(x, arr[i])
	}
	return x
}

// FileExisted checks whether filename exists in filesystem
func FileExisted(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil || os.IsExist(err)
}

type KeyType byte

// Supported key types
const (
	PK_ECDSA KeyType = 0x12
	PK_SM2   KeyType = 0x13
	PK_EDDSA KeyType = 0x14

	PK_P256_E  KeyType = 0x02
	PK_P256_O  KeyType = 0x03
	PK_P256_NC KeyType = 0x04
)

const (
	// ECDSA curve label
	CP224 byte = 1
	CP256 byte = 2
	CP384 byte = 3
	CP521 byte = 4

	// SM2 curve label
	CPSM2P256V1 byte = 20

	// ED25519 curve label
	ED25519 byte = 25
)

const err_generate = "key pair generation failed, "

func AddressFromVmCode(code []byte) Address {
	var addr Address
	temp := sha256.Sum256(code)
	md := ripemd160.New()
	md.Write(temp[:])
	md.Sum(addr[:0])

	return addr
}

type ECAlgorithm byte

const (
	ECDSA ECAlgorithm = iota
	SM2
)

type ECPrivateKey struct {
	Algorithm ECAlgorithm
	*ecdsa.PrivateKey
}

func (this *ECPrivateKey) Public() crypto.PublicKey {
	return &ECPrivateKey{Algorithm: this.Algorithm, PrivateKey: this.PrivateKey}
}

type ECPublicKey struct {
	Algorithm ECAlgorithm
	*ecdsa.PublicKey
}

// // PublicKey represents an ECDSA public key.
// type ECDSAPublicKey struct {
// 	Curve
// 	X, Y *big.Int
// }

// // PrivateKey represents an ECDSA private key.
// type ECDSAPrivateKey struct {
// 	ECDSAPublicKey
// 	D *big.Int
// }

func SerializePublicKey(key PublicKey) []byte {
	var buf bytes.Buffer
	switch t := key.(type) {
	case *ECPublicKey:
		switch t.Algorithm {
		case ECDSA:
			// Take P-256 as a special case
			if t.Params().Name == P256().Params().Name {
				return EncodePublicKey(t.PublicKey, true)
			}
			buf.WriteByte(byte(PK_ECDSA))
		case SM2:
			buf.WriteByte(byte(PK_SM2))
		}
		label, err := GetCurveLabel(t.Curve)
		if err != nil {
			panic(err)
		}
		buf.WriteByte(label)
		buf.Write(EncodePublicKey(t.PublicKey, true))
	case ed25519.PublicKey:
		buf.WriteByte(byte(PK_EDDSA))
		buf.WriteByte(ED25519)
		buf.Write([]byte(t))
	default:
		panic("unknown public key type")
	}

	return buf.Bytes()
}

func GetCurveLabel(c elliptic.Curve) (byte, error) {
	return GetNamedCurveLabel(c.Params().Name)
}

func GetNamedCurveLabel(name string) (byte, error) {
	switch strings.ToUpper(name) {
	case strings.ToUpper(P224().Params().Name):
		return CP224, nil
	case strings.ToUpper(P256().Params().Name):
		return CP256, nil
	case strings.ToUpper(P384().Params().Name):
		return CP384, nil
	case strings.ToUpper(P521().Params().Name):
		return CP521, nil
	case strings.ToUpper(SM2P256V1().Params().Name):
		return CPSM2P256V1, nil
	default:
		return 0, errors.New("unsupported elliptic curve")
	}
}

const (
	compress_even = 2
	compress_odd  = 3
	nocompress    = 4
)

func EncodePublicKey(key *ecdsa.PublicKey, compressed bool) []byte {
	if key == nil {
		panic("invalid argument: public key is nil")
	}

	length := (key.Curve.Params().BitSize + 7) >> 3
	buf := make([]byte, (length*2)+1)
	x := key.X.Bytes()
	copy(buf[length+1-len(x):], x)
	if compressed {
		if key.Y.Bit(0) == 0 {
			buf[0] = compress_even
		} else {
			buf[0] = compress_odd
		}
		return buf[:length+1]
	} else {
		buf[0] = nocompress
		y := key.Y.Bytes()
		copy(buf[length*2+1-len(y):], y)
		return buf
	}
}

func SortPublicKeys(list []PublicKey) []PublicKey {
	pl := publicKeyList(list)
	sort.Sort(pl)
	return pl
}

type publicKeyList []PublicKey

func (this publicKeyList) Len() int {
	return len(this)
}

func GetKeyType(p PublicKey) KeyType {
	switch t := p.(type) {
	case *ECPublicKey:
		switch t.Algorithm {
		case ECDSA:
			return PK_ECDSA
		case SM2:
			return PK_SM2
		default:
			panic("unknown public key type")
		}
	case ed25519.PublicKey:
		return PK_EDDSA
	default:
		panic("unknown public key type")
	}
}
func (this publicKeyList) Less(i, j int) bool {
	a, b := this[i], this[j]
	ta := GetKeyType(a)
	tb := GetKeyType(b)
	if ta != tb {
		return ta < tb
	}

	switch ta {
	case PK_ECDSA, PK_SM2:
		va := a.(*ECPublicKey)
		vb := b.(*ECPublicKey)
		ca, err := GetCurveLabel(va)
		if err != nil {
			panic(err)
		}
		cb, err := GetCurveLabel(vb)
		if err != nil {
			panic(err)
		}
		if ca != cb {
			return ca < cb
		}
		cmp := va.X.Cmp(vb.X)
		if cmp != 0 {
			return cmp < 0
		}
		cmp = va.Y.Cmp(vb.Y)
		return cmp < 0
	case PK_EDDSA:
		va := a.(ed25519.PublicKey)
		vb := b.(ed25519.PublicKey)
		return bytes.Compare(va, vb) < 0
	default:
		panic("error key type")
	}
	return true
}

func (this publicKeyList) Swap(i, j int) {
	this[i], this[j] = this[j], this[i]
}

// FindKey finds the specified public key in the list and returns its index
// or -1 if not found.
func FindKey(list []PublicKey, key PublicKey) int {
	for i, v := range list {
		if ComparePublicKey(v, key) {
			return i
		}
	}
	return -1
}

// ComparePublicKey checks whether the two public key are the same.
func ComparePublicKey(k0, k1 PublicKey) bool {
	if reflect.TypeOf(k0) != reflect.TypeOf(k1) {
		return false
	}

	switch v0 := k0.(type) {
	case *ECPublicKey:
		v1 := k1.(*ECPublicKey)
		if v0.Algorithm == v1.Algorithm && v0.Params().Name == v1.Params().Name && v0.X.Cmp(v1.X) == 0 {
			return true
		}

	case ed25519.PublicKey:
		v1 := k1.(ed25519.PublicKey)
		if bytes.Compare(v0, v1) == 0 {
			return true
		}
	}

	return false
}

// DeserializePublicKey parse the byte sequencce to a public key.
func DeserializePublicKey(data []byte) (PublicKey, error) {
	if len(data) <= 3 {
		return nil, errors.New("too short pubkey")
	}
	switch KeyType(data[0]) {
	case PK_ECDSA, PK_SM2:
		c, err := GetCurve(data[1])
		if err != nil {
			return nil, err
		}
		pub, err := DecodePublicKey(data[2:], c)
		if err != nil {
			return nil, err
		}
		pk := &ECPublicKey{PublicKey: pub}
		switch KeyType(data[0]) {
		case PK_ECDSA:
			pk.Algorithm = ECDSA
		case PK_SM2:
			pk.Algorithm = SM2
		default:
			return nil, errors.New("deserializing public key failed: unknown EC algorithm")
		}

		return pk, nil

	case PK_EDDSA:
		if data[1] == ED25519 {
			if len(data[2:]) != ed25519.PublicKeySize {
				return nil, errors.New("deserializing public key failed: invalid length for Ed25519 public key")
			}
			pk := make([]byte, ed25519.PublicKeySize)
			copy(pk, data[2:])
			return ed25519.PublicKey(pk), nil
		} else {
			return nil, errors.New("deserializing public key failed: unsupported EdDSA scheme")
		}

	case PK_P256_E, PK_P256_O, PK_P256_NC:
		pub, err := DecodePublicKey(data, P256())
		if err != nil {
			return nil, errors.New("deserializing public key failed: decode P-256 public key error")
		}

		pk := &ECPublicKey{
			Algorithm: ECDSA,
			PublicKey: pub,
		}
		return pk, nil

	default:
		return nil, errors.New("deserializing public key failed: unrecognized algorithm label")
	}

}

func GetCurve(label byte) (elliptic.Curve, error) {
	switch label {
	case CP224:
		return elliptic.P224(), nil
	case CP256:
		return elliptic.P256(), nil
	case CP384:
		return elliptic.P384(), nil
	case CP521:
		return elliptic.P521(), nil
	case CPSM2P256V1:
		return SM2P256V1(), nil
	default:
		return nil, errors.New("unknown elliptic curve")
	}

}

func DecodePublicKey(data []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	if curve == nil {
		return nil, errors.New("unknown curve")
	}

	length := (curve.Params().BitSize + 7) >> 3
	if len(data) < length+1 {
		return nil, errors.New("invalid data length")
	}

	var x, y *big.Int
	x = new(big.Int).SetBytes(data[1 : length+1])
	if data[0] == nocompress {
		if len(data) < length*2+1 {
			return nil, errors.New("invalid data length")
		}
		y = new(big.Int).SetBytes(data[length+1 : length*2+1])
		//TODO verify whether (x,y) is on the curve
		//if !IsOnCurve(curve, x, y) {
		//	return nil, errors.New("Point is not on the curve")
		//}
	} else if data[0] == compress_even || data[0] == compress_odd {
		return deCompress(int(data[0]&1), data[1:length+1], curve)
	} else {
		return nil, errors.New("unknown encoding mode")
	}

	return &ecdsa.PublicKey{
		X:     x,
		Y:     y,
		Curve: curve,
	}, nil
}

// deCompress is for computing the coordinate of Y based the coordinate of X
func deCompress(yTilde int, xValue []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	xCoord := big.NewInt(0)
	xCoord.SetBytes(xValue)

	curveParams := curve.Params()
	//y**2 = x**3 + A*x +B, A = -3, there is no A's clear definition in the realization of p256.
	paramA := big.NewInt(-3)
	//compute x**3 + A*x +B
	ySqare := big.NewInt(0)
	ySqare.Exp(xCoord, big.NewInt(2), curveParams.P)
	ySqare.Add(ySqare, paramA)
	ySqare.Mod(ySqare, curveParams.P)
	ySqare.Mul(ySqare, xCoord)
	ySqare.Mod(ySqare, curveParams.P)
	ySqare.Add(ySqare, curveParams.B)
	ySqare.Mod(ySqare, curveParams.P)

	yValue := curveSqrt(ySqare, curveParams)
	if nil == yValue {
		return nil, errors.New("Invalid point compression")
	}

	yCoord := big.NewInt(0)
	if (isEven(yValue) && 0 != yTilde) || (!isEven(yValue) && 1 != yTilde) {
		yCoord.Sub(curveParams.P, yValue)
	} else {
		yCoord.Set(yValue)
	}
	return &ecdsa.PublicKey{
		X:     xCoord,
		Y:     yCoord,
		Curve: curve,
	}, nil
}
func isEven(k *big.Int) bool {
	if k.Bit(0) == 0 {
		return true
	} else {
		return false
	}
}

// compute the coordinate of Y from Y**2
func curveSqrt(ySquare *big.Int, curve *elliptic.CurveParams) *big.Int {
	if curve.P.Bit(1) == 1 {
		tmp1 := big.NewInt(0)
		tmp1.Rsh(curve.P, 2)
		tmp1.Add(tmp1, big.NewInt(1))

		tmp2 := big.NewInt(0)
		tmp2.Exp(ySquare, tmp1, curve.P)

		tmp3 := big.NewInt(0)
		tmp3.Exp(tmp2, big.NewInt(2), curve.P)

		if 0 == tmp3.Cmp(ySquare) {
			return tmp2
		}
		return nil
	}

	qMinusOne := big.NewInt(0)
	qMinusOne.Sub(curve.P, big.NewInt(1))

	legendExponent := big.NewInt(0)
	legendExponent.Rsh(qMinusOne, 1)

	tmp4 := big.NewInt(0)
	tmp4.Exp(ySquare, legendExponent, curve.P)
	if 0 != tmp4.Cmp(big.NewInt(1)) {
		return nil
	}

	k := big.NewInt(0)
	k.Rsh(qMinusOne, 2)
	k.Lsh(k, 1)
	k.Add(k, big.NewInt(1))

	lucasParamQ := big.NewInt(0)
	lucasParamQ.Set(ySquare)
	fourQ := big.NewInt(0)
	fourQ.Lsh(lucasParamQ, 2)
	fourQ.Mod(fourQ, curve.P)

	seqU := big.NewInt(0)
	seqV := big.NewInt(0)

	for {
		lucasParamP := big.NewInt(0)
		for {
			tmp5 := big.NewInt(0)
			lucasParamP, _ = Prime(Reader, curve.P.BitLen())

			if lucasParamP.Cmp(curve.P) < 0 {
				tmp5.Mul(lucasParamP, lucasParamP)
				tmp5.Sub(tmp5, fourQ)
				tmp5.Exp(tmp5, legendExponent, curve.P)

				if 0 == tmp5.Cmp(qMinusOne) {
					break
				}
			}
		}

		seqU, seqV = fastLucasSequence(curve.P, lucasParamP, lucasParamQ, k)

		tmp6 := big.NewInt(0)
		tmp6.Mul(seqV, seqV)
		tmp6.Mod(tmp6, curve.P)
		if 0 == tmp6.Cmp(fourQ) {
			if 1 == seqV.Bit(0) {
				seqV.Add(seqV, curve.P)
			}
			seqV.Rsh(seqV, 1)
			return seqV
		}
		if (0 == seqU.Cmp(big.NewInt(1))) || (0 == seqU.Cmp(qMinusOne)) {
			break
		}
	}
	return nil
}

func getLowestSetBit(k *big.Int) int {
	i := 0
	for i = 0; k.Bit(i) != 1; i++ {
	}
	return i
}

// fastLucasSequence refer to https://en.wikipedia.org/wiki/Lucas_sequence
func fastLucasSequence(curveP, lucasParamP, lucasParamQ, k *big.Int) (*big.Int, *big.Int) {
	n := k.BitLen()
	s := getLowestSetBit(k)

	uh := big.NewInt(1)
	vl := big.NewInt(2)
	ql := big.NewInt(1)
	qh := big.NewInt(1)
	vh := big.NewInt(0).Set(lucasParamP)
	tmp := big.NewInt(0)

	for j := n - 1; j >= s+1; j-- {
		ql.Mul(ql, qh)
		ql.Mod(ql, curveP)

		if k.Bit(j) == 1 {
			qh.Mul(ql, lucasParamQ)
			qh.Mod(qh, curveP)

			uh.Mul(uh, vh)
			uh.Mod(uh, curveP)

			vl.Mul(vh, vl)
			tmp.Mul(lucasParamP, ql)
			vl.Sub(vl, tmp)
			vl.Mod(vl, curveP)

			vh.Mul(vh, vh)
			tmp.Lsh(qh, 1)
			vh.Sub(vh, tmp)
			vh.Mod(vh, curveP)
		} else {
			qh.Set(ql)

			uh.Mul(uh, vl)
			uh.Sub(uh, ql)
			uh.Mod(uh, curveP)

			vh.Mul(vh, vl)
			tmp.Mul(lucasParamP, ql)
			vh.Sub(vh, tmp)
			vh.Mod(vh, curveP)

			vl.Mul(vl, vl)
			tmp.Lsh(ql, 1)
			vl.Sub(vl, tmp)
			vl.Mod(vl, curveP)
		}
	}

	ql.Mul(ql, qh)
	ql.Mod(ql, curveP)

	qh.Mul(ql, lucasParamQ)
	qh.Mod(qh, curveP)

	uh.Mul(uh, vl)
	uh.Sub(uh, ql)
	uh.Mod(uh, curveP)

	vl.Mul(vh, vl)
	tmp.Mul(lucasParamP, ql)
	vl.Sub(vl, tmp)
	vl.Mod(vl, curveP)

	ql.Mul(ql, qh)
	ql.Mod(ql, curveP)

	for j := 1; j <= s; j++ {
		uh.Mul(uh, vl)
		uh.Mul(uh, curveP)

		vl.Mul(vl, vl)
		tmp.Lsh(ql, 1)
		vl.Sub(vl, tmp)
		vl.Mod(vl, curveP)

		ql.Mul(ql, ql)
		ql.Mod(ql, curveP)
	}

	return uh, vl
}

// Prime returns a number, p, of the given size, such that p is prime
// with high probability.
// Prime will return error for any error returned by rand.Read or if bits < 2.
func Prime(rand io.Reader, bits int) (p *big.Int, err error) {
	if bits < 2 {
		err = errors.New("crypto/rand: prime size must be at least 2-bit")
		return
	}

	b := uint(bits % 8)
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, (bits+7)/8)
	p = new(big.Int)

	bigMod := new(big.Int)

	for {
		_, err = io.ReadFull(rand, bytes)
		if err != nil {
			return nil, err
		}

		// Clear bits in the first byte to make sure the candidate has a size <= bits.
		bytes[0] &= uint8(int(1<<b) - 1)
		// Don't let the value be too small, i.e, set the most significant two bits.
		// Setting the top two bits, rather than just the top bit,
		// means that when two of these values are multiplied together,
		// the result isn't ever one bit short.
		if b >= 2 {
			bytes[0] |= 3 << (b - 2)
		} else {
			// Here b==1, because b cannot be zero.
			bytes[0] |= 1
			if len(bytes) > 1 {
				bytes[1] |= 0x80
			}
		}
		// Make the value odd since an even number this large certainly isn't prime.
		bytes[len(bytes)-1] |= 1

		p.SetBytes(bytes)

		// Calculate the value mod the product of smallPrimes. If it's
		// a multiple of any of these primes we add two until it isn't.
		// The probability of overflowing is minimal and can be ignored
		// because we still perform Miller-Rabin tests on the result.
		bigMod.Mod(p, smallPrimesProduct)
		mod := bigMod.Uint64()

	NextDelta:
		for delta := uint64(0); delta < 1<<20; delta += 2 {
			m := mod + delta
			for _, prime := range smallPrimes {
				if m%uint64(prime) == 0 && (bits > 6 || m != uint64(prime)) {
					continue NextDelta
				}
			}

			if delta > 0 {
				bigMod.SetUint64(delta)
				p.Add(p, bigMod)
			}
			break
		}

		// There is a tiny possibility that, by adding delta, we caused
		// the number to be one bit too long. Thus we check BitLen
		// here.
		if p.ProbablyPrime(20) && p.BitLen() == bits {
			return
		}
	}
}

var smallPrimesProduct = new(big.Int).SetUint64(16294579238595022365)
var smallPrimes = []uint8{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
}

func NewInvokeTransaction(gasPrice, gasLimit uint64, invokeCode []byte) *MutableTransaction {
	invokePayload := &InvokeCode{
		Code: invokeCode,
	}
	tx := &MutableTransaction{
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		TxType:   Invoke,
		Nonce:    rand.Uint32(),
		Payload:  invokePayload,
		Sigs:     make([]Sig, 0, 0),
	}
	return tx
}

func BuildNativeInvokeCode(contractAddress Address, version byte, method string, params []interface{}) ([]byte, error) {
	builder := NewParamsBuilder(new(bytes.Buffer))
	err := BuildNeoVMParam(builder, params)
	if err != nil {
		return nil, err
	}
	builder.EmitPushByteArray([]byte(method))
	builder.EmitPushByteArray(contractAddress[:])
	builder.EmitPushInteger(new(big.Int).SetInt64(int64(version)))
	builder.Emit(SYSCALL)
	builder.EmitPushByteArray([]byte(NATIVE_INVOKE_NAME))
	return builder.ToArray(), nil
}

var NATIVE_INVOKE_NAME = "Ontology.Native.Invoke"

//the 64 bit fixed-point number, precise 10^-8
type Fixed64 int64

func (f Fixed64) GetData() int64 {
	return int64(f)
}

//buildNeoVMParamInter build neovm invoke param code
func BuildNeoVMParam(builder *ParamsBuilder, smartContractParams []interface{}) error {
	//VM load params in reverse order
	for i := len(smartContractParams) - 1; i >= 0; i-- {
		switch v := smartContractParams[i].(type) {
		case bool:
			builder.EmitPushBool(v)
		case byte:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case int:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case uint:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case int32:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case uint32:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case int64:
			builder.EmitPushInteger(big.NewInt(int64(v)))
		case Fixed64:
			builder.EmitPushInteger(big.NewInt(int64(v.GetData())))
		case uint64:
			val := big.NewInt(0)
			builder.EmitPushInteger(val.SetUint64(uint64(v)))
		case string:
			builder.EmitPushByteArray([]byte(v))
		case *big.Int:
			builder.EmitPushInteger(v)
		case []byte:
			builder.EmitPushByteArray(v)
		case Address:
			builder.EmitPushByteArray(v[:])
		case Uint256:
			builder.EmitPushByteArray(v.ToArray())
		case []interface{}:
			err := BuildNeoVMParam(builder, v)
			if err != nil {
				return err
			}
			builder.EmitPushInteger(big.NewInt(int64(len(v))))
			builder.Emit(PACK)
		default:
			object := reflect.ValueOf(v)
			kind := object.Kind().String()
			if kind == "ptr" {
				object = object.Elem()
				kind = object.Kind().String()
			}
			switch kind {
			case "slice":
				ps := make([]interface{}, 0)
				for i := 0; i < object.Len(); i++ {
					ps = append(ps, object.Index(i).Interface())
				}
				err := BuildNeoVMParam(builder, []interface{}{ps})
				if err != nil {
					return err
				}
			case "struct":
				builder.EmitPushInteger(big.NewInt(0))
				builder.Emit(NEWSTRUCT)
				builder.Emit(TOALTSTACK)
				for i := 0; i < object.NumField(); i++ {
					field := object.Field(i)
					builder.Emit(DUPFROMALTSTACK)
					err := BuildNeoVMParam(builder, []interface{}{field.Interface()})
					if err != nil {
						return err
					}
					builder.Emit(APPEND)
				}
				builder.Emit(FROMALTSTACK)
			default:
				return fmt.Errorf("unsupported param:%s", v)
			}
		}
	}
	return nil
}

// AddressParseFromHexString returns parsed Address
func AddressFromHexString(s string) (Address, error) {
	hx, err := HexToBytes(s)
	if err != nil {
		return ADDRESS_EMPTY, err
	}
	return AddressParseFromBytes(ToArrayReverse(hx))
}

func AddressFromPubKey(pubkey PublicKey) Address {
	prog := ProgramFromPubKey(pubkey)

	return AddressFromVmCode(prog)
}

// GenerateKeyPair generates a pair of private and public keys in type t.
// opts is the necessary parameter(s), which is defined by the key type:
//     ECDSA: a byte specifies the elliptic curve, which defined in package ec
//     SM2:   same as ECDSA
//     EdDSA: a byte specifies the curve, only ED25519 supported currently.
func GenerateKeyPair(t KeyType, opts interface{}) (PrivateKey, PublicKey, error) {
	switch t {
	case PK_ECDSA, PK_SM2:
		param, ok := opts.(byte)
		if !ok {
			return nil, nil, errors.New(err_generate + "invalid EC options, 1 byte curve label excepted")
		}
		c, err := GetCurve(param)
		if err != nil {
			return nil, nil, errors.New(err_generate + err.Error())
		}

		if t == PK_ECDSA {
			return GenerateECKeyPair(c, Reader, ECDSA)
		} else {
			return GenerateECKeyPair(c, Reader, SM2)
		}

	case PK_EDDSA:
		param, ok := opts.(byte)
		if !ok {
			return nil, nil, errors.New(err_generate + "invalid EdDSA option")
		}

		if param == ED25519 {
			pub, pri, err := ed25519GenerateKey(Reader)
			return pri, pub, err
		} else {
			return nil, nil, errors.New(err_generate + "unsupported EdDSA scheme")
		}
	default:
		return nil, nil, errors.New(err_generate + "unknown algorithm")
	}
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func ed25519GenerateKey(rand io.Reader) (PublicKeyBytes, PrivateKeyBytes, error) {
	if rand == nil {
		rand = Reader
	}

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}

	privateKey := NewKeyFromSeed(seed)
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, privateKey[32:])

	return publicKey, privateKey, nil
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) PrivateKeyBytes {
	if l := len(seed); l != SeedSize {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}

	digest := sha512.Sum512(seed)
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var A ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], digest[:])
	GeScalarMultBase(&A, &hBytes)
	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	privateKey := make([]byte, PrivateKeySize)
	copy(privateKey, seed)
	copy(privateKey[32:], publicKeyBytes[:])

	return privateKey
}

type Signature struct {
	Scheme SignatureScheme
	Value  interface{}
}

type DSASignature struct {
	R, S  *big.Int
	Curve elliptic.Curve
}

type SM2Signature struct {
	DSASignature
	ID string
}

// Sign generates the signature for the input message @msg, using private key
// @pri and the signature scheme @scheme.
//
// Some signature scheme may use extra parameters, which could be inputted via
// the last argument @opt:
// - SM2 signature needs the user ID (string). If it is an empty string, the
//   default ID ("1234567812345678") would be used.
func Sign(scheme SignatureScheme, pri PrivateKey, msg []byte, opt interface{}) (sig *Signature, err error) {
	var res Signature
	res.Scheme = scheme
	switch key := pri.(type) {
	case *ECPrivateKey:
		hasher := GetHash(scheme)
		if hasher == nil {
			err = errors.New("signing failed: unknown scheme")
			return
		}

		if scheme == SM3withSM2 {
			id := ""
			if opt, ok := opt.(string); ok {
				id = opt
			}
			r, s, err0 := SM2Sign(Reader, key.PrivateKey, id, msg, hasher)
			if err0 != nil {
				err = err0
				return
			}
			res.Value = &SM2Signature{
				ID:           id,
				DSASignature: DSASignature{R: r, S: s, Curve: key.Curve},
			}
		} else if scheme == SHA224withECDSA ||
			scheme == SHA256withECDSA ||
			scheme == SHA384withECDSA ||
			scheme == SHA512withECDSA ||
			scheme == SHA3_224withECDSA ||
			scheme == SHA3_256withECDSA ||
			scheme == SHA3_384withECDSA ||
			scheme == SHA3_512withECDSA ||
			scheme == RIPEMD160withECDSA {

			hasher.Write(msg)
			digest := hasher.Sum(nil)

			r, s, err0 := ecdsa.Sign(Reader, key.PrivateKey, digest)
			if err0 != nil {
				err = err0
				return
			}
			res.Value = &DSASignature{R: r, S: s, Curve: key.Curve}
		} else {
			err = errors.New("signing failed: unmatched signature scheme and private key")
			return
		}

	case ed25519.PrivateKey:
		if scheme != SHA512withEDDSA {
			err = errors.New("signing failed: unmatched signature scheme and private key")
			return
		}
		res.Value = ed25519.Sign(key, msg)

	default:
		err = errors.New("signing failed: unknown type of private key")
		return
	}

	sig = &res
	return
}

// Combine the raw data with user ID, curve parameters and public key
// to generate the signed data used in Sign and Verify
func getZ(msg []byte, pub *ecdsa.PublicKey, userID string, hasher hash.Hash) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key should not be nil")
	}

	var c SM2Curve
	if t, ok := pub.Curve.(SM2Curve); !ok {
		return nil, errors.New("the curve type is not SM2Curve")
	} else {
		c = t
	}

	if len(userID) == 0 {
		userID = DEFAULT_ID
	}
	id := []byte(userID)
	len := len(id) * 8
	blen := []byte{byte((len >> 8) & 0xff), byte(len & 0xff)}

	hasher.Reset()
	hasher.Write(blen)
	hasher.Write(id)
	hasher.Write(c.ABytes())
	hasher.Write(c.Params().B.Bytes())
	hasher.Write(c.Params().Gx.Bytes())
	hasher.Write(c.Params().Gy.Bytes())
	hasher.Write(pub.X.Bytes())
	hasher.Write(pub.Y.Bytes())
	h := hasher.Sum(nil)
	return append(h, msg...), nil
}

// SM2Sign generates signature for the input message using the private key and id.
// It returns (r, s) as the signature or error.
func SM2Sign(rand io.Reader, priv *ecdsa.PrivateKey, id string, msg []byte, hasher hash.Hash) (r, s *big.Int, err error) {
	mz, err := getZ(msg, &priv.PublicKey, id, hasher)
	if err != nil {
		return
	}
	hasher.Reset()
	hasher.Write(mz)
	digest := hasher.Sum(nil)

	entropyLen := (priv.Params().BitSize + 7) >> 4
	if entropyLen > 32 {
		entropyLen = 32
	}

	entropy := make([]byte, entropyLen)
	_, err = io.ReadFull(rand, entropy)
	if err != nil {
		return
	}

	priKey := priv.D.Bytes()

	md := sha512.New()
	md.Write(priKey)
	md.Write(entropy)
	md.Write(digest[:])
	key := md.Sum(nil)[:32]

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	cspRng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	N := priv.Params().N
	if N.Sign() == 0 {
		err = errors.New("zero parameter")
		return
	}
	var k *big.Int
	e := new(big.Int).SetBytes(digest[:])
	for {
		for {
			k, err = randFieldElement(priv.Curve, cspRng)
			if err != nil {
				r = nil
				err = errors.New("randFieldElement error")
				return
			}

			r, _ = priv.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)
			if r.Sign() != 0 && new(big.Int).Add(r, k).Cmp(N) != 0 {
				break
			}
		}
		D := new(big.Int).SetBytes(priKey)
		rD := new(big.Int).Mul(D, r)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(D, one)
		var d1Inv *big.Int
		if opt, ok := priv.Curve.(invertible); ok {
			d1Inv = opt.Inverse(d1)
		} else {
			d1Inv = new(big.Int).ModInverse(d1, N)
		}
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}

	return
}

// AddressParseFromBytes returns parsed Address
func AddressParseFromBytes(f []byte) (Address, error) {
	if len(f) != ADDR_LEN {
		return ADDRESS_EMPTY, errors.New("[Common]: AddressParseFromBytes err, len != 20")
	}

	var addr Address
	copy(addr[:], f)
	return addr, nil
}

func ProgramFromPubKey(pubkey PublicKey) []byte {
	sink := ZeroCopySink{}
	EncodeSinglePubKeyProgramInto(&sink, pubkey)
	return sink.Bytes()
}

func GenerateECKeyPair(c elliptic.Curve, rand io.Reader, alg ECAlgorithm) (*ECPrivateKey, *ECPublicKey, error) {
	d, x, y, err := GenerateKey(c, rand)
	if err != nil {
		return nil, nil, errors.New("Generate ec key pair failed, " + err.Error())
	}
	pri := ECPrivateKey{
		Algorithm: alg,
		PrivateKey: &ecdsa.PrivateKey{
			D: new(big.Int).SetBytes(d),
			PublicKey: ecdsa.PublicKey{
				X:     x,
				Y:     y,
				Curve: c,
			},
		},
	}
	pub := ECPublicKey{
		Algorithm: alg,
		PublicKey: &pri.PublicKey,
	}
	return &pri, &pub, nil
}

func GetHash(scheme SignatureScheme) hash.Hash {
	switch scheme {
	case SHA224withECDSA:
		return crypto.SHA224.New()
	case SHA256withECDSA:
		return crypto.SHA256.New()
	case SHA384withECDSA:
		return crypto.SHA384.New()
	case SHA512withECDSA:
		return crypto.SHA512.New()
	case SHA3_224withECDSA:
		return crypto.SHA3_224.New()
	case SHA3_256withECDSA:
		return crypto.SHA3_256.New()
	case SHA3_384withECDSA:
		return crypto.SHA3_384.New()
	case SHA3_512withECDSA:
		return crypto.SHA3_512.New()
	case RIPEMD160withECDSA:
		return crypto.RIPEMD160.New()
	case SM3withSM2:
		return sm3.New()
	case SHA512withEDDSA:
		return crypto.SHA512.New()
	}
	return nil
}

func randFieldElement(c elliptic.Curve, rand io.Reader) (*big.Int, error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(rand, b)
	if err != nil {
		return nil, err
	}

	k := new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	n = n.Sub(n, one) //n-2

	// 1 <= k <= n-2
	k.Mod(k, n)
	k.Add(k, one)
	return k, nil
}



func PubKeysEqual(pks1, pks2 []PublicKey) bool {
	if len(pks1) != len(pks2) {
		return false
	}
	size := len(pks1)
	if size == 0 {
		return true
	}
	pkstr1 := make([]string, 0, size)
	for _, pk := range pks1 {
		pkstr1 = append(pkstr1, hex.EncodeToString(SerializePublicKey(pk)))
	}
	pkstr2 := make([]string, 0, size)
	for _, pk := range pks2 {
		pkstr2 = append(pkstr2, hex.EncodeToString(SerializePublicKey(pk)))
	}
	sort.Strings(pkstr1)
	sort.Strings(pkstr2)
	for i := 0; i < size; i++ {
		if pkstr1[i] != pkstr2[i] {
			return false
		}
	}
	return true
}
