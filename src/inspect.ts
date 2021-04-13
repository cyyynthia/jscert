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

import type { AsnSequenceNode, AsnSetNode } from './asn.js'
import buffer from 'buffer'
import { inspect } from 'util'
import { decodeAsn } from './asn.js'

function stringifyAsnSequence (asn: AsnSequenceNode | AsnSetNode, depth = 0, cursor = 0): [ string, number ] {
  const res: string[] = []

  for (const node of asn.value) {
    const headerLength = 1 + (node.length < 128 ? 1 : node.length < 256 ? 2 : 1 + Math.ceil(Math.log2(node.length) / 8))
    const dataKind = ([ 'sequence', 'set' ].includes(node.type)) ? 'cons:' : 'prim:'
    const dataType = ' '.repeat(depth) + node.type.toUpperCase().padEnd(18, ' ')

    const line = [
      `${cursor.toString().padStart(5, ' ')}:d=${depth.toString().padEnd(2)}`,
      `hl=${headerLength}`,
      `l=${node.length.toString().padStart(4, ' ')}`,
      dataKind,
      dataType
    ]

    if (dataKind === 'cons:') {
      res.push(line.join(' '))
      let [ seq, cur ] = stringifyAsnSequence(node as AsnSequenceNode, depth + 1, cursor + headerLength)
      cursor = cur
      res.push(seq)
    } else {
      if (node.value !== null) {
        let value = node.value
        if (value instanceof Buffer) {
          const ogMax = buffer.INSPECT_MAX_BYTES
          // @ts-expect-error -- This is actually allowed
          buffer.INSPECT_MAX_BYTES = 10
          value = inspect(value)
          // @ts-expect-error -- This is actually allowed
          buffer.INSPECT_MAX_BYTES = ogMax
        }
        line.push(`:${value.toString()}`)
      }
      cursor += headerLength + node.length
      res.push(line.join(' '))
    }
  }

  return [ res.join('\n'), cursor ]
}

export function inspectAsn (asn: Buffer | AsnSequenceNode) {
  if (asn instanceof Buffer) {
    asn = decodeAsn(asn)
  }

  if (asn.type !== 'sequence') {
    throw new TypeError(`invalid asn.1 node: expected a sequence, got ${asn.type}`)
  }

  const [ string ] = stringifyAsnSequence(asn)
  return string
}
