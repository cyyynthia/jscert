/*
 * Copyright (c) 2021 Cynthia K. Rey, All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import type { KeyObject } from 'crypto'
import type { AsnBitStringNode, AsnSequenceNode } from './asn.js'
import { sign as cryptoSign, verify as cryptoVerify } from 'crypto'
import { encodeAsn } from './asn.js'
import { typedAsnGetOrThrow } from './util.js'

// md* are excluded because too insecure. I don't think the compat issues
// from not supporting them at all outweighs the gain in security.
export type DigestAlgorithm =
  | 'sha1'
  | 'sha224'
  | 'sha256'
  | 'sha384'
  | 'sha512'

const digestByObjectId: Record<string, DigestAlgorithm> = {
  // RSA
  '1.2.840.113549.1.1.5': 'sha1', // sha1WithRSAEncryption
  '1.2.840.113549.1.1.14': 'sha224', // sha224WithRSAEncryption
  '1.2.840.113549.1.1.11': 'sha256', // sha256WithRSAEncryption
  '1.2.840.113549.1.1.12': 'sha384', // sha384WithRSAEncryption
  '1.2.840.113549.1.1.13': 'sha512', // sha512WithRSAEncryption

  // Elliptic curve
  '1.2.840.10045.4.1': 'sha1', // ecdsaWithSHA1
  '1.2.840.10045.4.3.1': 'sha224', // ecdsaWithSHA224
  '1.2.840.10045.4.3.2': 'sha256', // ecdsaWithSHA256
  '1.2.840.10045.4.3.3': 'sha384', // ecdsaWithSHA384
  '1.2.840.10045.4.3.4': 'sha512', // ecdsaWithSHA512
}

const objectIdByAlgorithm: { rsa: Record<DigestAlgorithm, string>, ec: Record<DigestAlgorithm, string> } = {
  rsa: {
    sha1: '1.2.840.113549.1.1.5', // sha1WithRSAEncryption
    sha224: '1.2.840.113549.1.1.14', // sha224WithRSAEncryption
    sha256: '1.2.840.113549.1.1.11', // sha256WithRSAEncryption
    sha384: '1.2.840.113549.1.1.12', // sha384WithRSAEncryption
    sha512: '1.2.840.113549.1.1.13', // sha512WithRSAEncryption
  },
  ec: {
    sha1: '1.2.840.10045.4.1', // ecdsaWithSHA1
    sha224: '1.2.840.10045.4.3.1', // ecdsaWithSHA224
    sha256: '1.2.840.10045.4.3.2', // ecdsaWithSHA256
    sha384: '1.2.840.10045.4.3.3', // ecdsaWithSHA384
    sha512: '1.2.840.10045.4.3.4', // ecdsaWithSHA512
  }
}

export function determineAlgorithm (key: KeyObject, digest: DigestAlgorithm) {
  if (!key.asymmetricKeyType || (key.asymmetricKeyType !== 'rsa' && key.asymmetricKeyType !== 'ec')) {
    throw new Error('cannot pick algorithm: invalid key')
  }

  return objectIdByAlgorithm[key.asymmetricKeyType][digest]
}

export function sign (data: Buffer, key: KeyObject, digest: DigestAlgorithm = 'sha256'): [ AsnSequenceNode, AsnBitStringNode ] {
  return [
    {
      type: 'sequence',
      value: [
        { type: 'oid', value: determineAlgorithm(key, digest), length: 0 },
        { type: 'null', value: null, length: 0 }
      ],
      length: 0
    },
    {
      type: 'bit_string',
      value: Buffer.concat([ Buffer.from([ 0x00 ]), cryptoSign(digest, data, key) ]),
      length: 0
    }
  ]
}

export function verify (data: AsnSequenceNode, key: KeyObject, algorithm: AsnSequenceNode, signature: AsnBitStringNode): boolean {
  return verifyRaw(encodeAsn(data), key, typedAsnGetOrThrow(algorithm, 0, 'oid').value, signature.value.slice(1))
}

export function verifyRaw (data: Buffer, key: KeyObject, algorithm: string, signature: Buffer): boolean {
  if (!(algorithm in digestByObjectId)) {
    throw new Error(`cannot verify signature: unknown algorithm ${algorithm}`)
  }

  try {
    return cryptoVerify(digestByObjectId[algorithm], data, key, signature)
  } catch {
    return false
  }
}
