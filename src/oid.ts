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

/*
todo: alg stuff

 ----- KEY TYPES
https://nodejs.org/docs/latest/api/crypto.html#crypto_keyobject_asymmetrickeytype
'rsa' (OID 1.2.840.113549.1.1.1)
'rsa-pss' (OID 1.2.840.113549.1.1.10)
'dsa' (OID 1.2.840.10040.4.1)
'ec' (OID 1.2.840.10045.2.1)
'x25519' (OID 1.3.101.110)
'x448' (OID 1.3.101.111)
'ed25519' (OID 1.3.101.112)
'ed448' (OID 1.3.101.113)
'dh' (OID 1.2.840.113549.1.3.1)

 ----- HASH TYPES
[ 'md4', '2.16.840.1.113719.1.2.8.95' ],
[ 'md4WithRSAEncryption', '1.3.14.3.2.4' ],
[ 'md5', '2.16.840.1.113719.1.2.8.50' ],
[ 'md5WithRSAEncryption', '1.2.840.113549.1.1.4' ],
[ 'ripemd160', '1.3.36.3.2.1' ],
[ 'sha1', '1.3.14.3.2.26' ],
[ 'sha1WithRSAEncryption', '1.2.840.113549.1.1.5' ],
[ 'sha224WithRSAEncryption', '1.2.840.113549.1.1.14' ],
[ 'sha256WithRSAEncryption', '1.2.840.113549.1.1.11' ],
[ 'sha384WithRSAEncryption', '1.2.840.113549.1.1.12' ],
[ 'sha512WithRSAEncryption', '1.2.840.113549.1.1.13' ],
[ 'shake128', '2.16.840.1.101.3.4.2.11' ],
[ 'shake256', '2.16.840.1.101.3.4.2.12' ],
[ 'whirlpool', '1.0.10118.3.0.55' ]
*/

type ObjectIdMap = {
  ids: {
    distinguishedName: Record<string, string>
  }
  distinguishedName: Record<ObjectIdMap['ids']['distinguishedName'][string], { name: keyof ObjectIdMap['ids']['distinguishedName'], type: AsnStringNode['type'] }>
}

const objectIds: ObjectIdMap = {
  ids: {
    distinguishedName: {
      commonName: '2.5.4.3',
      country: '2.5.4.6',
      locality: '2.5.4.7',
      state: '2.5.4.8',
      organization: '2.5.4.10',
      organizationalUnit: '2.5.4.11',
      emailAddress: '1.2.840.113549.1.9.1'
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
