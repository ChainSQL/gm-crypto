// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/cipher"
	"crypto/hmac"

	"github.com/peersafe/gm-crypto/sm3"
	"github.com/peersafe/gm-crypto/sm4"
)

const VersionGMSSL = 0x0101 // GM/T 0024-2014

// GMTLS crypto suite
const suiteGM = 1 << 4

const SM3 crypto.Hash = 255

// A list of cipher suite IDs that are, or have been, implemented by this
// package.
const (
	//GM crypto suites ID  Taken from GM/T 0024-2014
	GMTLS_ECDHE_SM2_WITH_SM1_SM3 uint16 = 0xe001
	GMTLS_SM2_WITH_SM1_SM3       uint16 = 0xe003
	GMTLS_IBSDH_WITH_SM1_SM3     uint16 = 0xe005
	GMTLS_IBC_WITH_SM1_SM3       uint16 = 0xe007
	GMTLS_RSA_WITH_SM1_SM3       uint16 = 0xe009
	GMTLS_RSA_WITH_SM1_SHA1      uint16 = 0xe00a
	GMTLS_ECDHE_SM2_WITH_SM4_SM3 uint16 = 0xe011
	GMTLS_SM2_WITH_SM4_SM3       uint16 = 0xe013
	GMTLS_IBSDH_WITH_SM4_SM3     uint16 = 0xe015
	GMTLS_IBC_WITH_SM4_SM3       uint16 = 0xe017
	GMTLS_RSA_WITH_SM4_SM3       uint16 = 0xe019
	GMTLS_RSA_WITH_SM4_SHA1      uint16 = 0xe01a
)

var gmCipherSuites = []*cipherSuite{
	{GMTLS_SM2_WITH_SM4_SM3, 16, 32, 16, eccSM2KA, suiteGM, cipherSM4, macSM3, nil},
}

func getCipherSuites(c *Config) []uint16 {
	s := c.CipherSuites
	if s == nil {
		s = []uint16{GMTLS_SM2_WITH_SM4_SM3}
	}
	return s
}

func eccSM2KA(version uint16) keyAgreement {
	return &eccSM2KeyAgreement{
		isRSA:   false,
		version: version,
	}
}

// func cipherSM4(key, iv []byte, isRead bool) interface{} {
// 	block, _ := sm4.NewCipher(key, iv)
// 	return block
// }

func cipherSM4(key, iv []byte, isRead bool) interface{} {
	block, _ := sm4.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func macSM3(version uint16, key []byte) macFunction {
	return tls10MAC{hmac.New(newConstantTimeHash(sm3.New), key)}
}

func eccGMKA(version uint16) keyAgreement {
	return &eccSM2KeyAgreement{
		version: version,
	}
}

// mutualCipherSuite returns a cipherSuite given a list of supported
// ciphersuites and the id requested by the peer.
func mutualCipherSuiteGM(have []uint16, want uint16) *cipherSuite {
	for _, id := range have {
		if id == want {
			for _, suite := range gmCipherSuites {
				if suite.id == want {
					return suite
				}
			}
			return nil
		}
	}
	return nil
}

type GMSupport struct {
}

func (support *GMSupport) GetVersion() uint16 {
	return VersionGMSSL
}

func (support *GMSupport) IsAvailable() bool {
	return true
}

func (support *GMSupport) cipherSuites() []*cipherSuite {
	return gmCipherSuites
}
