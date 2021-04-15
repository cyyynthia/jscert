# jscert
[![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/G2G71TSDF)<br>
[![License](https://img.shields.io/github/license/cyyynthia/jscert.svg?style=flat-square)](https://github.com/cyyynthia/jscert/blob/mistress/LICENSE)

A fast, lightweight & dependency-free NodeJS library to read, write and manipulate X.509 certificates.

**WARNING**: For the time being, you shouldn't pass untrusted data to the lib or unexpected things might happen to your
cat. While the lib should be working for *valid* data, it lacks on proper hardening of the parsing bits and proper
data validation/error handling, so maliciously crafted bits of data may cause some damage.

I may, in the future, try this lib against a fuzzer and make sure it's as safe as I can get it to be. For now, only
use the lib with data you trust!!

## Install
Soon:tm:
<!--
The library is alpha-quality, potentially broken and doesn't do a lot of things yet.

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
