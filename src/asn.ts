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

export type AsnBooleanNode = { type: 'boolean', value: boolean }
export type AsnIntegerNode = { type: 'integer', value: number }
export type AsnBitStringNode = { type: 'bit_string', value: Buffer }
export type AsnOctetStringNode = { type: 'octet_string', value: Buffer }
export type AsnNullNode = { type: 'null', value: null }
export type AsnObjectIdNode = { type: 'oid', value: string }
export type AsnUtf8StringNode = { type: 'utf8_string', value: string }
export type AsnPrintableStringNode = { type: 'printable_string', value: string }
export type AsnIa5StringNode = { type: 'ia5_string', value: string }
export type AsnSequenceNode = { type: 'sequence', value: AsnNode[] }
export type AsnSetNode = { type: 'set', value: AsnNode[] }
export type AsnCustomNode = { type: 'custom', tag: number, value: Buffer }
export type AsnNode =
  | AsnBooleanNode
  | AsnIntegerNode
  | AsnBitStringNode
  | AsnOctetStringNode
  | AsnNullNode
  | AsnObjectIdNode
  | AsnUtf8StringNode
  | AsnPrintableStringNode
  | AsnIa5StringNode
  | AsnSequenceNode
  | AsnSetNode
  | AsnCustomNode

type Definitions = {
  ids: Record<Exclude<AsnNode['type'], 'custom'>, number>
  [id: number]: {
    id: Exclude<AsnNode['type'], 'custom'>
    decode: (buf: Buffer) => any
    encode: (buf: any) => Buffer
  }
}

const defs: Definitions = {
  ids: {
    boolean: 0x01,
    integer: 0x02,
    bit_string: 0x03,
    octet_string: 0x04,
    null: 0x05,
    oid: 0x06,
    utf8_string: 0x0c,
    printable_string: 0x13,
    ia5_string: 0x16,
    sequence: 0x30,
    set: 0x31
  },

  [0x01]: {
    id: 'boolean',
    decode: (buf: Buffer): boolean => Boolean(buf[0]),
    encode: (bool: boolean): Buffer => Buffer.from([ Number(bool) ])
  },
  [0x02]: {
    id: 'integer',
    decode: (buf: Buffer): number => decodeInteger(buf),
    encode: (int: number): Buffer => encodeInteger(int)
  },
  [0x03]: {
    id: 'bit_string', // todo - https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-bit-string
    decode: (buf: Buffer): Buffer => buf,
    encode: (bit: Buffer): Buffer => bit
  },
  [0x04]: {
    id: 'octet_string', // todo - https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-octet-string
    decode: (buf: Buffer): Buffer => buf,
    encode: (bit: Buffer): Buffer => bit
  },
  [0x05]: {
    id: 'null',
    decode: (): null => null,
    encode: (): Buffer => Buffer.alloc(0)
  },
  [0x06]: {
    id: 'oid',
    decode: (buf: Buffer): string => decodeObjectId(buf),
    encode: (oid: string): Buffer => encodeObjectId(oid)
  },
  [0x0c]: {
    id: 'utf8_string',
    decode: (buf: Buffer): string => buf.toString(),
    encode: (str: string): Buffer => Buffer.from(str)
  },
  [0x13]: {
    id: 'printable_string',
    decode: (buf: Buffer): string => buf.toString(),
    encode: (str: string): Buffer => Buffer.from(str)
  },
  [0x16]: {
    id: 'ia5_string',
    decode: (buf: Buffer): string => buf.toString(),
    encode: (str: string): Buffer => Buffer.from(str)
  },
  [0x30]: {
    id: 'sequence',
    decode: (buf: Buffer): AsnNode[] => decodeSequence(buf),
    encode: (seq: AsnNode[]): Buffer => encodeSequence(seq)
  },
  [0x31]: {
    id: 'set',
    decode: (buf: Buffer): AsnNode[] => decodeSequence(buf),
    encode: (set: AsnNode[]): Buffer => encodeSequence(set)
  }
}

function decodeLength (buf: Buffer): [ number, number ] {
  if ((buf[0] & 128) === 0) {
    return [ 1, buf[0] ]
  }

  const len = buf[0] ^ 128
  return [ 1 + len, buf.slice(1, 1 + len).reduce((a, b) => (a << 8) + b, 0) ]
}

function encodeLength (length: number): Buffer {
  if (length < 128) {
    return Buffer.from([ length ])
  }

  const res = []
  while (length !== 0) {
    res.unshift(length ^ 256)
    length = length >> 8
  }

  res.unshift(res.length | 128)
  return Buffer.from(res)
}

function decodeInteger (buf: Buffer): number {
  let mult = 1
  if (buf[0] & 128) {
    buf[0] = buf[0] ^ 128
    mult = -1
  }

  return buf.reduce((a, b) => (a << 8) + b, 0) * mult
}

function encodeInteger (integer: number): Buffer {
  const negative = integer < 0
  integer = Math.abs(integer)
  const res: number[] = []
  while (integer !== 0) {
    const byte = integer ^ (res.length ? 256 : 128)
    integer = integer >> 8
    res.unshift(byte)
  }
  if (!res.length) res.push(0)
  if (negative) res[0] = res[0] | 128
  return Buffer.from(res)
}

function decodeObjectId (buf: Buffer): string {
  let res = `${Math.floor(buf[0] / 40)}.${buf[0] % 40}`
  let acc = 0
  for (const byte of buf.slice(1)) {
    if (byte & 128) {
      acc = (acc << 7) + ((byte << 1) ^ 256)
    } else if (acc) {
      res += `.${(acc << 6) + ((byte | 128) ^ 128)}`
      acc = 0
    } else {
      res += `.${byte}`
    }
  }

  return res
}

function encodeObjectId (oid: string): Buffer {
  const [ bit1, bit2, ...parts ] = oid.split('.').map(Number)
  const res = [ (bit1 * 40) + bit2 ]

  for (let part of parts) {
    const buf = []
    while (part !== 0) {
      const bit = part ^ 128
      part = part >> 8
      buf.unshift(buf.length ? (bit | 128) : bit)
    }
    res.push(...buf)
  }
  return Buffer.from(res)
}

function decodeSequence (buf: Buffer): AsnNode[] {
  const res: AsnNode[] = []
  let cursor = 0
  while (cursor < buf.length) {
    const type = buf[cursor++]
    const [ readLenBytes, len ] = decodeLength(buf.slice(cursor))
    const chunk = buf.slice(cursor + readLenBytes, cursor + readLenBytes + len)
    cursor += readLenBytes + len

    if ((type >> 6) === 0) {
      if (!(type in defs)) {
        throw new Error(`invalid ASN.1: unknown type 0x${type.toString(16)}`)
      }

      res.push({ type: defs[type].id, value: defs[type].decode(chunk) })
    } else {
      res.push({ type: 'custom', tag: type, value: chunk })
    }
  }

  return res
}

function encodeSequence (seq: AsnNode[]): Buffer {
  return Buffer.concat(
    seq.map((node) => {
      if (node.type === 'custom') {
        return Buffer.concat([ Buffer.from([ node.tag ]), encodeLength(node.value.length), node.value ])
      }

      const id = defs.ids[node.type]
      const buf = defs[id].encode(node.value)
      return Buffer.concat([ Buffer.from([ id ]), encodeLength(buf.length), buf ])
    })
  )
}

export function decodeAsn (buffer: Buffer): AsnNode[] {
  if (buffer[0] !== 0x30) {
    throw new TypeError('malformed ASN.1: does not start with a sequence')
  }

  return (decodeSequence(buffer)[0] as AsnSequenceNode).value
}

export function encodeAsn (asn: AsnNode[]): Buffer {
  const buf = encodeSequence(asn)
  return Buffer.concat([ Buffer.from([ defs.ids.sequence ]), encodeLength(buf.length), buf ])
}
