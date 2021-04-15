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

import type { AsnStringNode } from './asn.js'

export type SupportedPublicKeyAlgorithm =
  | 'rsa'
  | 'rsa-pss'
  | 'dsa'
  | 'ec'
  | 'x25519'
  | 'x448'
  | 'ed25519'
  | 'ed448'
  | 'dh'

export type SupportedSignatureAlgorithm =
  | 'md4'
  | 'md4WithRSAEncryption'
  | 'md5'
  | 'md5WithRSAEncryption'
  | 'ripemd160'
  | 'sha1'
  | 'sha1WithRSAEncryption'
  | 'sha224WithRSAEncryption'
  | 'sha256WithRSAEncryption'
  | 'sha384WithRSAEncryption'
  | 'sha512WithRSAEncryption'
  | 'shake128'
  | 'shake256'
  | 'whirlpool'

type ObjectIdMap = {
  ids: {
    distinguishedName: Record<string, { oid: string, type: AsnStringNode['type'] }>
    publicKeyAlgorithm: Record<SupportedPublicKeyAlgorithm, string>
    signatureAlgorithm: Record<SupportedSignatureAlgorithm, string>
  }
  distinguishedName: Record<ObjectIdMap['ids']['distinguishedName'][string]['oid'], { name: keyof ObjectIdMap['ids']['distinguishedName'], type: AsnStringNode['type'] }>,
  publicKeyAlgorithm: Record<ObjectIdMap['ids']['publicKeyAlgorithm'][SupportedPublicKeyAlgorithm], SupportedPublicKeyAlgorithm>
  signatureAlgorithm: Record<ObjectIdMap['ids']['signatureAlgorithm'][SupportedSignatureAlgorithm], SupportedSignatureAlgorithm>
}

const objectIds: ObjectIdMap = {
  ids: {
    distinguishedName: {
      commonName: { oid: '2.5.4.3', type: 'utf8_string' },
      country: { oid: '2.5.4.6', type: 'printable_string' },
      locality: { oid: '2.5.4.7', type: 'utf8_string' },
      state: { oid: '2.5.4.8', type: 'utf8_string' },
      organization: { oid: '2.5.4.10', type: 'utf8_string' },
      organizationalUnit: { oid: '2.5.4.11', type: 'utf8_string' },
      emailAddress: { oid: '1.2.840.113549.1.9.1', type: 'ia5_string' },
    },
    publicKeyAlgorithm: {
      rsa: '1.2.840.113549.1.1.1',
      'rsa-pss': '1.2.840.113549.1.1.10',
      dsa: '1.2.840.10040.4.1',
      ec: '1.2.840.10045.2.1',
      x25519: '1.3.101.110',
      x448: '1.3.101.111',
      ed25519: '1.3.101.112',
      ed448: '1.3.101.113',
      dh: '1.2.840.113549.1.3.1',
    },
    signatureAlgorithm: {
      md4: '2.16.840.1.113719.1.2.8.95',
      md4WithRSAEncryption: '1.3.14.3.2.4',
      md5: '2.16.840.1.113719.1.2.8.50',
      md5WithRSAEncryption: '1.2.840.113549.1.1.4',
      ripemd160: '1.3.36.3.2.1',
      sha1: '1.3.14.3.2.26',
      sha1WithRSAEncryption: '1.2.840.113549.1.1.5',
      sha224WithRSAEncryption: '1.2.840.113549.1.1.14',
      sha256WithRSAEncryption: '1.2.840.113549.1.1.11',
      sha384WithRSAEncryption: '1.2.840.113549.1.1.12',
      sha512WithRSAEncryption: '1.2.840.113549.1.1.13',
      shake128: '2.16.840.1.101.3.4.2.11',
      shake256: '2.16.840.1.101.3.4.2.12',
      whirlpool: '1.0.10118.3.0.55',
    }
  },

  distinguishedName: {
    '2.5.4.3': { name: 'commonName', type: 'utf8_string' },
    '2.5.4.6': { name: 'country', type: 'printable_string' },
    '2.5.4.7': { name: 'locality', type: 'utf8_string' },
    '2.5.4.8': { name: 'state', type: 'utf8_string' },
    '2.5.4.10': { name: 'organization', type: 'utf8_string' },
    '2.5.4.11': { name: 'organizationalUnit', type: 'utf8_string' },
    '1.2.840.113549.1.9.1': { name: 'emailAddress', type: 'ia5_string' },
  },
  publicKeyAlgorithm: {
    '1.2.840.113549.1.1.1': 'rsa',
    '1.2.840.113549.1.1.10': 'rsa-pss',
    '1.2.840.10040.4.1': 'dsa',
    '1.2.840.10045.2.1': 'ec',
    '1.3.101.110': 'x25519',
    '1.3.101.111': 'x448',
    '1.3.101.112': 'ed25519',
    '1.3.101.113': 'ed448',
    '1.2.840.113549.1.3.1': 'dh',
  },
  signatureAlgorithm: {
    '2.16.840.1.113719.1.2.8.95': 'md4',
    '1.3.14.3.2.4': 'md4WithRSAEncryption',
    '2.16.840.1.113719.1.2.8.50': 'md5',
    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
    '1.3.36.3.2.1': 'ripemd160',
    '1.3.14.3.2.26': 'sha1',
    '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
    '1.2.840.113549.1.1.14': 'sha224WithRSAEncryption',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
    '2.16.840.1.101.3.4.2.11': 'shake128',
    '2.16.840.1.101.3.4.2.12': 'shake256',
    '1.0.10118.3.0.55': 'whirlpool',
  },
}

export default objectIds
