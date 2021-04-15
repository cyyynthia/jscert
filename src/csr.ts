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

import type { RsaPublicKey, RsaPrivateKey } from 'crypto'
import { verify, createPublicKey, constants as CryptoConstants } from 'crypto'
import { decodePem, encodePem } from './pem.js'
import { decodeAsn, encodeAsn, typedGetOrThrow } from './asn.js'
import { distinguishedName } from './oid.js'

type x509DN = {
  country?: string
  state?: string
  locality?: string
  organization?: string
  organizationalUnit?: string
  commonName?: string
  emailAddress?: string
}

const LABEL = 'CERTIFICATE REQUEST'

export default class CertificateSigningRequest {
  distinguishedName: x509DN
  publicKey: RsaPublicKey

  // There will always be either one of those set. When there's no pk, the object is readonly.
  privateKey: RsaPrivateKey | null
  #signature?: Buffer

  constructor (distinguishedName: x509DN, publicKey: RsaPublicKey, privateKey: RsaPrivateKey)
  constructor (distinguishedName: x509DN, publicKey: RsaPublicKey, signature: Buffer)
  constructor (distinguishedName: x509DN, publicKey: RsaPublicKey, keyData: RsaPrivateKey | Buffer) {
    this.distinguishedName = distinguishedName
    this.publicKey = publicKey
    if (keyData instanceof Buffer) {
      this.#signature = keyData
      this.privateKey = null
    } else {
      this.privateKey = keyData
    }
  }

  toAsn (): Buffer {
    if (!this.#signature) {
      console.log(this.privateKey!)
    }
    return Buffer.alloc(0) // todo
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
    //const keyAlg = typedGetOrThrow(typedGetOrThrow(certInfoKey, 0, 'sequence'), 0, 'oid').value
    const keyBits = typedGetOrThrow(certInfoKey, 1, 'bit_string').value.slice(1) // todo: remove slice (bit string memes)
    const key: RsaPublicKey = {
      key: createPublicKey({ key: keyBits, format: 'der', type: 'pkcs1' }), // todo: do something with the alg
      padding: CryptoConstants.RSA_PKCS1_PADDING
    }

    // -- Read key information
    //const signatureAlg = typedGetOrThrow(typedGetOrThrow(decoded, 1, 'sequence'), 0, 'oid').value
    const signature = typedGetOrThrow(decoded, 2, 'bit_string').value.slice(1) // todo: remove slice (bit string memes)

    // todo: use algorthm specified in signatureAlg
    if (!verify('rsa-sha256', encodeAsn(certInfo), key.key, signature)) {
      throw new Error('invalid csr: cannot verify signature')
    }

    // -- Decode certificate information
    if (certInfoVersion.value !== 0) throw new Error(`invalid csr: expected version to be 0, got ${certInfoVersion.value}`)
    const subjectEntries: Array<[ string, string ]> = []
    for (const entry of certInfoSubject.value) {
      if (entry.type !== 'set') throw new TypeError(`type mismatch: expected set got ${entry.type}`)

      const seq = entry.value
      if (seq.type !== 'sequence') throw new TypeError(`type mismatch: expected sequence got ${seq.type}`)
      subjectEntries.push([ typedGetOrThrow(seq, 0, 'oid').value, typedGetOrThrow(seq, 1, 'string').value ])
    }

    // todo: support all the OIDs?
    const subject = Object.fromEntries(subjectEntries)
    const dn: x509DN = {}
    if (distinguishedName.country in subject) dn.country = subject[distinguishedName.country]
    if (distinguishedName.state in subject) dn.state = subject[distinguishedName.state]
    if (distinguishedName.locality in subject) dn.locality = subject[distinguishedName.locality]
    if (distinguishedName.organization in subject) dn.organization = subject[distinguishedName.organization]
    if (distinguishedName.organizationalUnit in subject) dn.organizationalUnit = subject[distinguishedName.organizationalUnit]
    if (distinguishedName.commonName in subject) dn.commonName = subject[distinguishedName.commonName]
    if (distinguishedName.emailAddress in subject) dn.emailAddress = subject[distinguishedName.emailAddress]

    return new CertificateSigningRequest(dn, key, signature)
  }

  static fromPem (pem: string): CertificateSigningRequest {
    const { label, asn } = decodePem(pem)
    if (label !== LABEL) {
      throw new Error(`not a valid csr: invalid label: expected ${LABEL}, got ${label}`)
    }

    return CertificateSigningRequest.fromAsn(asn)
  }
}
