# jscert
[![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/G2G71TSDF)<br>
[![License](https://img.shields.io/github/license/cyyynthia/jscert.svg?style=flat-square)](https://github.com/cyyynthia/jscert/blob/mistress/LICENSE)

A fast, lightweight & dependency-free NodeJS library to read, write and manipulate X.509 certificates.

## Install
Soon:tm:
<!--
**Note**: This library uses ES Modules.
```
pnpm i @cyyynthia/jscert
yarn add @cyyynthia/jscert
npm i @cyyynthia/jscert
```
-->

## Usage
full usage soon:tm:

### Decode/encode PEM
```ts
// note: for now the implementation can only read a string with a **single** PEM entity in it.
import { readFileSync } from 'fs'
import { decodePem, encodePem } from '@cyyynthia/jscert'

const pem = readFileSync('./certificate-signing-request.pem', 'utf8')
console.log(decodePem(pem)) // ~> { label: 'CERTIFICATE REQUEST', asn: <Buffer ...> }

const asn = ...
console.log(encodePem(asn, 'CERTIFICATE REQUEST')) // ~> -----BEGIN CERTIFICATE REQUEST----- ...
```

### Decode/encode raw ASN.1
```ts
import { decodeAsn, encodeAsn } from '@cyyynthia/jscert'

const decoded = decodeAsn(asnBuffer)
const encoded = encodeAsn(decoded)
```

### Inspect ASN.1
```ts
import { inspectAsn } from '@cyyynthia/jscert'

// This produces (roughly) the same output as `openssl asn1parse`
console.log(inspectAsn(asnBuffer))
// --OR--
const decoded = decodeAsn(asnBuffer)
console.log(inspectAsn(decoded))
```
