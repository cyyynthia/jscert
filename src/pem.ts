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

const PEM_SPLIT_REG = /.{1,64}/g

export type PemEntry = { label: string, asn: Buffer }

// todo: allow decoding streams?

export function decodePem (pem: string): PemEntry { // todo: pem files can contain multiple things in it
  const data = pem.trim().split('\n')
  const header = data.shift()
  const footer = data.pop()
  if (!header || !footer || !data.length) {
    throw new Error('invalid pem: not enough data')
  }

  if (!header.startsWith('-----BEGIN ') || !header.endsWith('-----')) {
    throw new Error('invalid pem: invalid header')
  }

  if (!footer.startsWith('-----END ') || !footer.endsWith('-----')) {
    throw new Error('invalid pem: invalid footer')
  }

  const label = header.slice(11, header.length - 5)
  if (label !== footer.slice(9, footer.length - 5)) {
    throw new Error('invalid pem: mismatched header/footer labels')
  }

  return {
    label: label,
    asn: Buffer.from(data.join(''), 'base64')
  }
}

export function encodePem (asn: Buffer, label: string): string {
  const data = asn.toString('base64').match(PEM_SPLIT_REG)!.join('\n')
  return `-----BEGIN ${label}-----\n${data}\n-----END ${label}-----`
}
