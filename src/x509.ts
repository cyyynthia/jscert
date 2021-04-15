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

import type { AsnSequenceNode, AsnSetNode, AsnStringNode } from './asn.js'
import { typedAsnGetOrThrow } from './util.js'

type ObjectIdMap = {
  byProp: Record<keyof DistinguishedName, { oid: string, type: AsnStringNode['type'] }>
  byId: Record<string, { name: keyof DistinguishedName, type: AsnStringNode['type'] }>
}

const stringTypes = [ 'utf8_string', 'printable_string', 'ia5_string' ]

const ids: ObjectIdMap = {
  byProp: {
    commonName: { oid: '2.5.4.3', type: 'utf8_string' },
    country: { oid: '2.5.4.6', type: 'printable_string' },
    locality: { oid: '2.5.4.7', type: 'utf8_string' },
    state: { oid: '2.5.4.8', type: 'utf8_string' },
    organization: { oid: '2.5.4.10', type: 'utf8_string' },
    organizationalUnit: { oid: '2.5.4.11', type: 'utf8_string' },
    emailAddress: { oid: '1.2.840.113549.1.9.1', type: 'ia5_string' },
  },

  byId: {
    '2.5.4.3': { name: 'commonName', type: 'utf8_string' },
    '2.5.4.6': { name: 'country', type: 'printable_string' },
    '2.5.4.7': { name: 'locality', type: 'utf8_string' },
    '2.5.4.8': { name: 'state', type: 'utf8_string' },
    '2.5.4.10': { name: 'organization', type: 'utf8_string' },
    '2.5.4.11': { name: 'organizationalUnit', type: 'utf8_string' },
    '1.2.840.113549.1.9.1': { name: 'emailAddress', type: 'ia5_string' },
  }
}

export type DistinguishedName = {
  country?: string
  state?: string
  locality?: string
  organization?: string
  organizationalUnit?: string
  commonName?: string
  emailAddress?: string
}

export function parseDistinguishedName (seq: AsnSequenceNode): DistinguishedName {
  const res: DistinguishedName = {}
  for (const entry of seq.value) {
    if (entry.type !== 'set') throw new TypeError(`type mismatch: expected set got ${entry.type}`)
    const seq = entry.value
    if (seq.type !== 'sequence') throw new TypeError(`type mismatch: expected sequence got ${seq.type}`)

    const oid = typedAsnGetOrThrow(seq, 0, 'oid').value
    if (oid in ids.byId) { // todo: throw un unrecognized values? or ignore is fine?
      const type = ids.byId[oid]
      if (!stringTypes.includes(seq.value[1].type)) {
        throw new TypeError(`type mismatch: expected string got ${seq.value[1].type}`)
      }

      res[type.name] = seq.value[1].value as string
    }
  }

  return res
}

export function serializeDistinguishedName (dn: DistinguishedName): AsnSequenceNode {
  const subject: AsnSetNode[] = []
  let dnProp: keyof DistinguishedName
  for (dnProp in dn) {
    if (dnProp in dn) {
      subject.push({
        type: 'set',
        value: {
          type: 'sequence',
          value: [
            { type: 'oid', value: ids.byProp[dnProp].oid, length: 0 },
            { type: ids.byProp[dnProp].type, value: dn[dnProp]!, length: 0 },
          ],
          length: 0
        },
        length: 0
      })
    }
  }

  return {
    type: 'sequence',
    value: subject,
    length: 0
  }
}
