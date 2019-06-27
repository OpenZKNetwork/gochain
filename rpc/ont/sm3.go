package ont

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

/*
 * Package sm3 implements the Chinese SM3 Digest Algorithm,
 * according to "go/src/crypto/sha256"
 * author: weizhang <d5c5ceb0@gmail.com>
 * 2017.02.24
 */

import (
	"hash"
)

// The size of a SM3 checksum in bytes.
const Size = 32

// The blocksize of SM3 in bytes.
const BlockSize = 64

const (
	chunk = 64
	init0 = 0x7380166F
	init1 = 0x4914B2B9
	init2 = 0x172442D7
	init3 = 0xDA8A0600
	init4 = 0xA96F30BC
	init5 = 0x163138AA
	init6 = 0xE38DEE4D
	init7 = 0xB0FB0E4E
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	h   [8]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7
	d.nx = 0
	d.len = 0
}

// New returns a new hash.Hash computing the SM3 checksum.
func SM3New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *digest) Sum(in []byte) []byte {
	// Make a copy of d0 so that caller can keep writing and summing.
	d := *d0
	hash := d.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() [Size]byte {
	len := d.len
	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (56 - 8*i))
	}
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	h := d.h[:]

	var digest [Size]byte
	for i, s := range h {
		digest[i*4] = byte(s >> 24)
		digest[i*4+1] = byte(s >> 16)
		digest[i*4+2] = byte(s >> 8)
		digest[i*4+3] = byte(s)
	}

	return digest
}

// Sum returns the SM3 checksum of the data.
func Sum(data []byte) [Size]byte {
	var d digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}




func block(dig *digest, p []byte) {
	blockGeneric(dig, p)
}

func blockGeneric(dig *digest, p []byte) {
	var w [68]uint32
	var w1 [64]uint32
	var ss1, ss2, tt1, tt2 uint32

	h0, h1, h2, h3, h4, h5, h6, h7 := dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7]
	for len(p) >= chunk {
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}
		for i := 16; i < 68; i++ {
			w[i] = sm3_p1(w[i-16]^w[i-9]^sm3_rotl(w[i-3], 15)) ^ sm3_rotl(w[i-13], 7) ^ w[i-6]
		}

		for i := 0; i < 64; i++ {
			w1[i] = w[i] ^ w[i+4]
		}

		a, b, c, d, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7

		for j := 0; j < 64; j++ {
			ss1 = sm3_rotl(sm3_rotl(a, 12)+e+sm3_rotl(sm3_t(j), uint32(j)), 7)
			ss2 = ss1 ^ sm3_rotl(a, 12)
			tt1 = sm3_ff(a, b, c, j) + d + ss2 + w1[j]
			tt2 = sm3_gg(e, f, g, j) + h + ss1 + w[j]
			d = c
			c = sm3_rotl(b, 9)
			b = a
			a = tt1
			h = g
			g = sm3_rotl(f, 19)
			f = e
			e = sm3_p0(tt2)
		}

		h0 ^= a
		h1 ^= b
		h2 ^= c
		h3 ^= d
		h4 ^= e
		h5 ^= f
		h6 ^= g
		h7 ^= h

		p = p[chunk:]
	}

	dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7] = h0, h1, h2, h3, h4, h5, h6, h7
}

func sm3_t(j int) uint32 {
	if j >= 16 {
		return 0x7A879D8A
	} else {
		return 0x79CC4519
	}
}

func sm3_ff(x, y, z uint32, j int) uint32 {
	if j >= 16 {
		return ((x | y) & (x | z) & (y | z))
	} else {
		return x ^ y ^ z
	}

}

func sm3_gg(x, y, z uint32, j int) uint32 {
	if j >= 16 {
		return ((x & y) | ((^x) & z))
	} else {
		return x ^ y ^ z
	}
}

func sm3_rotl(x, n uint32) uint32 {
	return (x << (n % 32)) | (x >> (32 - (n % 32)))
}

func sm3_p0(x uint32) uint32 {
	return x ^ sm3_rotl(x, 9) ^ sm3_rotl(x, 17)
}

func sm3_p1(x uint32) uint32 {
	return x ^ sm3_rotl(x, 15) ^ sm3_rotl(x, 23)
}
