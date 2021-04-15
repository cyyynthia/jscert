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

type ObjectIdMap = {
  ids: {
    distinguishedName: Record<string, { oid: string, type: AsnStringNode['type'] }>
  }
  distinguishedName: Record<ObjectIdMap['ids']['distinguishedName'][string]['oid'], { name: keyof ObjectIdMap['ids']['distinguishedName'], type: AsnStringNode['type'] }>
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
  }
}

export default objectIds
