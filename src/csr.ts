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
import type { AsnSequenceNode } from './asn.js'
import type { DigestAlgorithm } from './sign.js'

import { createPublicKey } from 'crypto'
import { sameKeyPair, typedAsnGetOrThrow } from './util.js'
import { decodePem, encodePem } from './pem.js'
import { decodeAsn, encodeAsn } from './asn.js'
import { sign, verify } from './sign.js'
import { DistinguishedName, parseDistinguishedName, serializeDistinguishedName } from './x509.js'
import Certificate, { createFromProps } from './cert.js'

type CsrOptions = {
  digest?: DigestAlgorithm
}

const LABEL = 'CERTIFICATE REQUEST'

export default class CertificateSigningRequest {
  distinguishedName: DistinguishedName
  options: CsrOptions
  key: KeyObject
  #encoded?: Buffer

  constructor (distinguishedName: DistinguishedName, key: KeyObject, options: CsrOptions = {}) {
    if (key.asymmetricKeyType !== 'rsa' && key.asymmetricKeyType !== 'ec') {
      throw new Error('cannot create csr: invalid key type. only rsa and ec are supported')
    }

    this.distinguishedName = distinguishedName
    this.options = options
    this.key = key
  }

  createSelfSignedCertificate (expiry: Date, privateKey?: KeyObject): Certificate {
    const key = privateKey ?? this.key
    if (key.type !== 'private') throw new Error('cannot sign csr: no private key provided')
    if (!sameKeyPair(this.key, key)) throw new Error('cannot sign csr: public and private key mismatch')
    return createFromProps(this.key, key, this.options.digest ?? 'sha256', this.distinguishedName, this.distinguishedName, expiry, true)
  }

  createCertificate (expiry: Date, issuer: Certificate, issuerKey: KeyObject): Certificate {
    if (issuerKey.type !== 'private') throw new Error('cannot sign csr: no private key provided')
    if (!sameKeyPair(issuer.key, issuerKey)) throw new Error('cannot sign csr: public and private key mismatch')
    return createFromProps(this.key, issuerKey, this.options.digest ?? 'sha256', issuer.subject, this.distinguishedName, expiry, true)
  }

  toAsn (): Buffer {
    if (this.#encoded) {
      // This is defined when the CSR has been decoded using fromAsn (or fromPem). no need to re-encode things
      return this.#encoded
    }

    if (this.key.type !== 'private') {
      throw new Error('cannot encode csr: provided key is not the private key')
    }

    const certInfo: AsnSequenceNode = {
      type: 'sequence',
      value: [
        { type: 'integer', value: 0n, length: 0 },
        serializeDistinguishedName(this.distinguishedName),
        decodeAsn(createPublicKey(this.key).export({ format: 'der', type: 'spki' })).value[0]
      ],
      length: 0
    }

    return encodeAsn({
      type: 'sequence',
      value: [
        certInfo,
        ...sign(encodeAsn(certInfo), this.key, this.options.digest ?? 'sha256')
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
    const certInfo = typedAsnGetOrThrow(decoded, 0, 'sequence')
    const certInfoVersion = typedAsnGetOrThrow(certInfo, 0, 'integer')
    const certInfoSubject = typedAsnGetOrThrow(certInfo, 1, 'sequence')
    const certInfoKey = typedAsnGetOrThrow(certInfo, 2, 'sequence')

    // -- Read public key information
    const key = createPublicKey({ key: encodeAsn(certInfoKey), format: 'der', type: 'spki' })

    // -- Verify signature
    if (!verify(certInfo, key, typedAsnGetOrThrow(decoded, 1, 'sequence'), typedAsnGetOrThrow(decoded, 2, 'bit_string'))) {
      throw new Error('invalid csr: cannot verify signature')
    }

    // -- Decode certificate information
    if (certInfoVersion.value !== 0n) throw new Error(`invalid csr: expected version to be 0, got ${certInfoVersion.value}`)
    const dn = parseDistinguishedName(certInfoSubject)

    const csr = new CertificateSigningRequest(dn, key)
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
