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

import { randomBytes, createPublicKey } from 'crypto'
import { typedAsnGetOrThrow } from './util.js'
import { decodePem, encodePem } from './pem.js'
import { AsnSequenceNode, decodeAsn, encodeAsn } from './asn.js'
import { determineAlgorithm, DigestAlgorithm, sign, verify, verifyRaw } from './sign.js'
import { DistinguishedName, parseDistinguishedName, serializeDistinguishedName } from './x509.js'

const LABEL = 'CERTIFICATE'

export default class Certificate {
  serial: BigInt
  signatureAlg: string
  subject: DistinguishedName
  issuer: DistinguishedName
  notBefore: Date
  notAfter: Date
  key: KeyObject
  signature: Buffer
  selfSigned: boolean
  #encoded: Buffer
  #encodedData: Buffer

  constructor (serial: BigInt, signatureAlg: string, subject: DistinguishedName, issuer: DistinguishedName, notBefore: Date, notAfter: Date, key: KeyObject, signature: Buffer, selfSigned: boolean, cert: Buffer, certData: Buffer) {
    this.serial = serial
    this.signatureAlg = signatureAlg
    this.subject = subject
    this.issuer = issuer
    this.notBefore = notBefore
    this.notAfter = notAfter
    this.key = key
    this.signature = signature
    this.selfSigned = selfSigned
    this.#encoded = cert
    this.#encodedData = certData
  }

  verify (cert?: Certificate): boolean {
    // Expired or not valid yet
    if (Date.now() < this.notBefore.getTime() || Date.now() > this.notAfter.getTime()) return false

    // This function is NOT responsible for verifying if a cert is in a trustchain. This is a job for userland logic.
    // The function is also NOT responsible for verifying if the provided certificate is trustable.
    if (this.selfSigned) return true

    if (!cert) throw new Error('cannot verify certificate: parent certificate required!')
    return verifyRaw(this.#encodedData, cert.key, this.signatureAlg, this.signature)
  }

  toAsn (): Buffer {
    return this.#encoded
  }

  toPem (): string {
    return encodePem(this.toAsn(), LABEL)
  }

  static fromAsn (asn: Buffer): Certificate {
    // todo: strict validation!! (untrusted data memes)
    const decoded = decodeAsn(asn).value[0]
    if (decoded.type !== 'sequence') {
      throw new Error(`invalid csr: expected first child node to be a sequence, got ${decoded.type}`)
    }

    // -- Read certificate information
    const certInfo = typedAsnGetOrThrow(decoded, 0, 'sequence')
    if (certInfo.value[0].type === 'custom') certInfo.value.shift()
    const serialNumber = typedAsnGetOrThrow(certInfo, 0, 'integer').value
    const signatureAlg = typedAsnGetOrThrow(typedAsnGetOrThrow(certInfo, 1, 'sequence'), 0, 'oid').value
    const certInfoIssuer = typedAsnGetOrThrow(certInfo, 2, 'sequence')
    const certInfoExpiry = typedAsnGetOrThrow(certInfo, 3, 'sequence')
    const certInfoSubject = typedAsnGetOrThrow(certInfo, 4, 'sequence')
    const certInfoKey = typedAsnGetOrThrow(certInfo, 5, 'sequence')

    // -- Read public key information
    const key = createPublicKey({ key: encodeAsn(certInfoKey), format: 'der', type: 'spki' })

    // -- Verify signature
    const selfSigned = verify(certInfo, key, typedAsnGetOrThrow(decoded, 1, 'sequence'), typedAsnGetOrThrow(decoded, 2, 'bit_string'))
    const notBeforeInfo = certInfoExpiry.value[0]
    const notAfterInfo = certInfoExpiry.value[1]
    if (notBeforeInfo.type !== 'utc_time' && notBeforeInfo.type !== 'generalized_time') {
      throw new Error(`invalid certificate: expected a date got ${notBeforeInfo.type}`)
    }
    if (notAfterInfo.type !== 'utc_time' && notAfterInfo.type !== 'generalized_time') {
      throw new Error(`invalid certificate: expected a date got ${notAfterInfo.type}`)
    }

    const subject = parseDistinguishedName(certInfoSubject)
    const issuer = parseDistinguishedName(certInfoIssuer)
    return new Certificate(
      serialNumber,
      signatureAlg,
      subject,
      issuer,
      notBeforeInfo.value,
      notAfterInfo.value,
      key,
      typedAsnGetOrThrow(decoded, 2, 'bit_string').value.slice(1),
      selfSigned,
      asn,
      encodeAsn(certInfo)
    )
  }

  static fromPem (pem: string): Certificate {
    const { label, asn } = decodePem(pem)
    if (label !== LABEL) {
      throw new Error(`not a valid csr: invalid label: expected ${LABEL}, got ${label}`)
    }

    return Certificate.fromAsn(asn)
  }
}

export function createFromProps (key: KeyObject, signKey: KeyObject, digest: DigestAlgorithm, issuer: DistinguishedName, subject: DistinguishedName, expiry: Date, self: boolean): Certificate {
  const serialBuf = randomBytes(16)
  if (serialBuf[0] & 128) serialBuf[0] = serialBuf[0] ^ 128
  const res = serialBuf.reduce((a, b) => (BigInt(a) << 8n) + BigInt(b), 0n)
  const serial = (serialBuf[0] & 128) ? -res : res
  const signAlg = determineAlgorithm(signKey, digest)
  const now = new Date()
  now.setMilliseconds(0)
  const certInfo: AsnSequenceNode = {
    type: 'sequence',
    value: [
      { type: 'integer', value: serial, length: 0 },
      {
        type: 'sequence',
        value: [
          { type: 'oid', value: signAlg, length: 0 },
          { type: 'null', value: null, length: 0 }
        ],
        length: 0
      },
      serializeDistinguishedName(issuer),
      {
        type: 'sequence',
        value: [
          { type: 'generalized_time', value: now, length: 0 },
          { type: 'generalized_time', value: expiry, length: 0 }
        ],
        length: 0
      },
      serializeDistinguishedName(subject),
      decodeAsn(createPublicKey(key).export({ format: 'der', type: 'spki' })).value[0]
    ],
    length: 0
  }

  const asnCertInfo = encodeAsn(certInfo)
  const signature = sign(asnCertInfo, signKey, digest)
  return new Certificate(
    serial,
    signAlg,
    subject,
    issuer,
    now,
    expiry,
    key,
    signature[1].value.slice(1),
    self,
    encodeAsn({ type: 'sequence', value: [ certInfo, ...signature ], length: 0 }),
    asnCertInfo
  )
}
