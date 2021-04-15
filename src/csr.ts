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
import type { AsnSequenceNode, AsnSetNode } from './asn.js'
import type { SupportedSignatureAlgorithm } from './oid.js'

import { createPublicKey, sign, verify } from 'crypto'
import { decodePem, encodePem } from './pem.js'
import { decodeAsn, encodeAsn, typedGetOrThrow } from './asn.js'
import objectIds from './oid.js'

type x509DN = {
  country?: string
  state?: string
  locality?: string
  organization?: string
  organizationalUnit?: string
  commonName?: string
  emailAddress?: string
}

type Algorithm = {
  signature: SupportedSignatureAlgorithm
}

const LABEL = 'CERTIFICATE REQUEST'

export default class CertificateSigningRequest {
  distinguishedName: x509DN
  algorithm: Algorithm
  key: KeyObject
  #encoded?: Buffer

  constructor (distinguishedName: x509DN, key: KeyObject, algorithm: Algorithm) {
    this.distinguishedName = distinguishedName
    this.algorithm = algorithm
    this.key = key
  }

  toAsn (): Buffer {
    if (this.#encoded) {
      // This is defined when the CSR has been decoded using fromAsn (or fromPem), which yields a readonly csr
      return this.#encoded
    }

    const subject: AsnSetNode[] = []
    for (const dnProp in this.distinguishedName) {
      if (dnProp in this.distinguishedName) {
        subject.push({
          type: 'set',
          value: {
            type: 'sequence',
            value: [
              { type: 'oid', value: objectIds.ids.distinguishedName[dnProp].oid, length: 0 },
              { type: objectIds.ids.distinguishedName[dnProp].type, value: this.distinguishedName[dnProp as keyof x509DN] as string, length: 0 },
            ],
            length: 0
          },
          length: 0
        })
      }
    }

    const certInfo: AsnSequenceNode = {
      type: 'sequence',
      value: [
        { type: 'integer', value: 0, length: 0 },
        { type: 'sequence', value: subject, length: 0 },
        decodeAsn(createPublicKey(this.key).export({ format: 'der', type: 'spki' })).value[0]
      ],
      length: 0
    }

    return encodeAsn({
      type: 'sequence',
      value: [
        certInfo,
        {
          type: 'sequence',
          value: [
            { type: 'oid', value: objectIds.ids.signatureAlgorithm[this.algorithm.signature], length: 0 },
            { type: 'null', value: null, length: 0 }
          ],
          length: 0
        },
        {
          type: 'bit_string',
          value: Buffer.concat([ Buffer.from([ 0x00 ]), sign(this.algorithm.signature, encodeAsn(certInfo), this.key) ]),
          length: 0
        },
      ],
      length: 0
    })
  }

  toPem (): string {
    return encodePem(this.toAsn(), LABEL)
  }

  static fromAsn (asn: Buffer): CertificateSigningRequest {
    // todo: strict validation!! (untrusted data memes)
    const decoded = decodeAsn(asn).value[0]
    if (decoded.type !== 'sequence') {
      throw new Error(`invalid csr: expected first child node to be a sequence, got ${decoded.type}`)
    }

    // -- Read certificate information
    const certInfo = typedGetOrThrow(decoded, 0, 'sequence')
    const certInfoVersion = typedGetOrThrow(certInfo, 0, 'integer')
    const certInfoSubject = typedGetOrThrow(certInfo, 1, 'sequence')
    const certInfoKey = typedGetOrThrow(certInfo, 2, 'sequence')

    // -- Read public key information
    const key = createPublicKey({ key: encodeAsn(certInfoKey), format: 'der', type: 'spki' })

    // -- Read key information
    const signatureAlgOid = typedGetOrThrow(typedGetOrThrow(decoded, 1, 'sequence'), 0, 'oid').value
    if (!(signatureAlgOid in objectIds.signatureAlgorithm)) {
      throw new Error(`unsupported signature algorithm (oid ${signatureAlgOid})`)
    }

    const signatureAlg = objectIds.signatureAlgorithm[signatureAlgOid]
    const signature = typedGetOrThrow(decoded, 2, 'bit_string').value.slice(1)
    if (!verify(signatureAlg, encodeAsn(certInfo), key, signature)) {
      throw new Error('invalid csr: cannot verify signature')
    }

    // -- Decode certificate information
    if (certInfoVersion.value !== 0) throw new Error(`invalid csr: expected version to be 0, got ${certInfoVersion.value}`)
    const dn: x509DN = {}
    for (const entry of certInfoSubject.value) {
      if (entry.type !== 'set') throw new TypeError(`type mismatch: expected set got ${entry.type}`)
      const seq = entry.value
      if (seq.type !== 'sequence') throw new TypeError(`type mismatch: expected sequence got ${seq.type}`)

      const oid = typedGetOrThrow(seq, 0, 'oid').value
      if (oid in objectIds.distinguishedName) { // todo: throw un unrecognized values? or ignore is fine?
        const type = objectIds.distinguishedName[oid]
        dn[type.name as keyof x509DN] = typedGetOrThrow(seq, 1, type.type).value
      }
    }

    const csr = new CertificateSigningRequest(dn, key, { signature: signatureAlg })
    csr.#encoded = asn
    return csr
  }

  static fromPem (pem: string): CertificateSigningRequest {
    const { label, asn } = decodePem(pem)
    if (label !== LABEL) {
      throw new Error(`not a valid csr: invalid label: expected ${LABEL}, got ${label}`)
    }

    return CertificateSigningRequest.fromAsn(asn)
  }
}
