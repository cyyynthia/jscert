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

// todo: harden the parsing part! needs fuzzing and proper handling of untrusted data
// todo: allow decoding streams?

export type AsnBooleanNode = { type: 'boolean', value: boolean, length: number }
export type AsnIntegerNode = { type: 'integer', value: number, length: number }
export type AsnBitStringNode = { type: 'bit_string', value: Buffer, length: number }
export type AsnOctetStringNode = { type: 'octet_string', value: Buffer, length: number }
export type AsnNullNode = { type: 'null', value: null, length: number }
export type AsnObjectIdNode = { type: 'oid', value: string, length: number }
export type AsnUtf8StringNode = { type: 'utf8_string', value: string, length: number }
export type AsnPrintableStringNode = { type: 'printable_string', value: string, length: number }
export type AsnIa5StringNode = { type: 'ia5_string', value: string, length: number }
export type AsnUtcTimeNode = { type: 'utc_time', value: Date, length: number }
export type AsnGeneralizedTimeNode = { type: 'generalized_time', value: Date, length: number }
export type AsnSequenceNode = { type: 'sequence', value: AsnNode[], length: number }
export type AsnSetNode = { type: 'set', value: AsnNode, length: number }
export type AsnCustomNode = { type: 'custom', tag: number, value: Buffer, length: number }
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
  | AsnUtcTimeNode
  | AsnGeneralizedTimeNode
  | AsnSequenceNode
  | AsnSetNode
  | AsnCustomNode

export type AsnStringNode =
  | AsnUtf8StringNode
  | AsnPrintableStringNode
  | AsnIa5StringNode

type Definitions = {
  ids: Record<Exclude<AsnNode['type'], 'custom'>, number>
  [id: number]: {
    id: Exclude<AsnNode['type'], 'custom'>
    decode: (buf: Buffer) => any
    encode: (buf: any) => Buffer
  }
}

const DATE_UTC_RE = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:(\d{2}))?(Z|(?:([+-])(\d{2})(\d{2})))?$/
const DATE_GENERIC_RE = /^(\d{4})(\d{2})(\d{2})(\d{2})(?:(\d{2})(?:(\d{2})(?:\.(\d{1,3}))?)?)?(Z|(?:([+-])(\d{2})(\d{2})))?$/

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
    utc_time: 0x17,
    generalized_time: 0x18,
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
  [0x17]: {
    id: 'utc_time',
    decode: (buf: Buffer): Date => decodeDate(buf, true),
    encode: (date: Date): Buffer => encodeDate(date, true)
  },
  [0x18]: {
    id: 'generalized_time',
    decode: (buf: Buffer): Date => decodeDate(buf, false),
    encode: (date: Date): Buffer => encodeDate(date, false)
  },
  [0x30]: {
    id: 'sequence',
    decode: (buf: Buffer): AsnNode[] => decodeSequence(buf),
    encode: (seq: AsnNode[]): Buffer => encodeSequence(seq)
  },
  [0x31]: {
    id: 'set',
    decode: (buf: Buffer): AsnNode => decodeSequence(buf)[0],
    encode: (set: AsnNode): Buffer => encodeSequence([ set ])
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
      const bit = (part & 0xff) | 0x80
      buf.unshift(!buf.length ? bit ^ 0x80 : bit)
      part = part >> 7
    }
    res.push(...buf)
  }
  return Buffer.from(res)
}

function decodeDate (buf: Buffer, utc: boolean): Date {
  const encoded = buf.toString()
  let year, month, day, hour, minute, second, milli
  if (utc) {
    const parsed = encoded.match(DATE_UTC_RE)
    if (!parsed) throw new Error('invalid asn.1: invalid utc date')

    year = Number(parsed[1])
    year += year > 50 ? 1900 : 2000 // https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
    month = Number(parsed[2])
    day = Number(parsed[3])
    hour = Number(parsed[4])
    minute = Number(parsed[5])
    second = parsed[6] ? Number(parsed[6]) : 0
    milli = 0
    if (parsed[7] !== 'Z') {
      if (parsed[8] === '+') {
        hour += Number(parsed[9])
        minute += Number(parsed[10])
      } else {
        hour -= Number(parsed[9])
        minute -= Number(parsed[10])
      }
    }
  } else {
    const parsed = encoded.match(DATE_GENERIC_RE)
    if (!parsed) throw new Error('invalid asn.1: invalid generic date')
    year = Number(parsed[1])
    month = Number(parsed[2])
    day = Number(parsed[3])
    hour = Number(parsed[4])
    minute = parsed[5] ? Number(parsed[5]) : 0
    second = parsed[6] ? Number(parsed[6]) : 0
    milli = parsed[7] ? Number(`0.${parsed[7]}`) * 1000 : 0

    if (!parsed[8]) {
      minute += new Date().getTimezoneOffset()
    } else if (parsed[8] !== 'Z') {
      if (parsed[9] === '+') {
        hour += Number(parsed[10])
        minute += Number(parsed[11])
      } else {
        hour -= Number(parsed[10])
        minute -= Number(parsed[11])
      }
    }
  }

  const date = new Date(0)
  date.setUTCFullYear(year)
  date.setUTCMonth(month - 1)
  date.setUTCDate(day)
  date.setUTCHours(hour)
  date.setUTCMinutes(minute)
  date.setUTCSeconds(second)
  date.setUTCMilliseconds(milli)
  return date
}

function encodeDate (date: Date, utc: boolean): Buffer {
  const ms = date.getUTCMilliseconds()
  const parts = [
    utc ? date.getUTCFullYear() % 100 : date.getUTCFullYear(),
    date.getUTCMonth() + 1,
    date.getUTCDate(),
    date.getUTCHours(),
    date.getUTCMinutes(),
    date.getUTCSeconds(),
    utc || !ms ? void 0 : (ms / 1000).toFixed(3)
  ]

  return Buffer.from(parts.filter(Boolean).map((n) => n!.toString().padStart(2, '0')).join('') + 'Z')
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
        throw new Error(`invalid asn.1: unknown type 0x${type.toString(16)}`)
      }

      res.push({ type: defs[type].id, value: defs[type].decode(chunk), length: len })
    } else {
      res.push({ type: 'custom', tag: type, value: chunk, length: len })
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

export function decodeAsn (buffer: Buffer): AsnSequenceNode {
  if (buffer[0] !== 0x30) {
    throw new TypeError('malformed asn.1: does not start with a sequence')
  }

  return { type: 'sequence', value: decodeSequence(buffer), length: buffer.length }
}

export function encodeAsn (asn: AsnSequenceNode): Buffer {
  const buf = encodeSequence(asn.value)
  return Buffer.concat([ Buffer.from([ defs.ids.sequence ]), encodeLength(buf.length), buf ])
}

export function typedGetOrThrow<T extends AsnNode['type']> (sequence: AsnSequenceNode, item: number, type: T): AsnNode & { type: T } {
  if (sequence.type !== 'sequence') {
    throw new TypeError(`type mismatch: expected source to be a sequence, got ${sequence.type}`)
  }

  const node = sequence.value[item]
  if (!node) {
    throw new Error('sequence item out of range')
  }

  if (node.type !== type) {
    throw new TypeError(`type mismatch: expected ${type} got ${node.type}`)
  }

  return node as AsnNode & { type: Extract<T, 'string'> }
}
