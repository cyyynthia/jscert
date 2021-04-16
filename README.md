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
The library is alpha-quality, potentially broken and doesn't do a lot of things.

**Note**: This library uses ES Modules.
```
pnpm i @cyyynthia/jscert
yarn add @cyyynthia/jscert
npm i @cyyynthia/jscert
```

## Usage
### Create a Certificate Signing Request
```ts
import { writeFileSync } from 'fs'
import { generateKeyPairSync } from 'crypto'
import { CertificateSigningRequest, encodePem } from '@cyyynthia/jscert'

// The public key can be ignored here since the CSR expects a private key to sign the data,
// and the public key bit will be derived from it.
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const dn = {
  country: 'FR',
  state: 'Occitanie',
  locality: 'Toulouse',
  organization: 'Borkenware',
  organizationalUnit: 'DSI',
  commonName: '*.borkenware.localhost',
  emailAddress: 'cyyynthia@borkenware.com'
}

const csr = new CertificateSigningRequest(dn, privateKey)

// Write the key & the csr
writeFileSync('./private-key.pem', encodePem(privateKey.export({ format: 'der', type: 'pkcs1' }), 'RSA PRIVATE KEY'))
writeFileSync('./certificate-signing-request.pem', csr.toPem()) // .toAsn() is also available
```

### Read a Certificate Signing Request
```ts
import { readFileSync } from 'fs'
import { CertificateSigningRequest } from '@cyyynthia/jscert'

const pem = readFileSync('./certificate-signing-request.pem', 'utf8')
const csr = CertificateSigningRequest.fromPem(pem) // .fromAsn(asnBuffer) is also available

console.log(csr)
```

### Turn a CSR into a self-signed Certificate
```ts
import { readFileSync } from 'fs'
import { CertificateSigningRequest } from '@cyyynthia/jscert'

const expiry = new Date(Date.now() + 365 * 86400e3) // A year (roughly) from now
const csr = new CertificateSigningRequest(...)
// If the CSR wasn't created with new CertificateSigningRequest,
// the operation will fail as the private key would be unknown.
// You can pass the private key as a parameter in this case.
// The key you pass must match the public key!!
const cert = csr.createSelfSignedCertificate(expiry) // or csr.selfSign(expiry, privateKey)

console.log(cert.toPem()) // .toAsn() is also available
```

### Turn a CSR into a signed Certificate
```ts
import { readFileSync } from 'fs'
import { CertificateSigningRequest, Certificate } from '@cyyynthia/jscert'

const issuerCert = Certificate.fromPem(...)
const issuerPrivateKey = ... // PrivateKeyObject

const expiry = new Date(Date.now() + 365 * 86400e3) // A year (roughly) from now
const pem = readFileSync('./certificate-signing-request.pem', 'utf8')
const csr = CertificateSigningRequest.fromPem(pem)
const cert = csr.createCertificate(issuerCert, issuerPrivateKey, expiry) // The certificate and the private key must match!!

console.log(cert.toPem()) // .toAsn() is also available
```

### Turn a CSR into a signed Certificate
```ts
import { readFileSync } from 'fs'
import { CertificateSigningRequest, Certificate } from '@cyyynthia/jscert'

const issuerCert = Certificate.fromPem(...)
const issuerPrivateKey = ... // PrivateKeyObject

const pem = readFileSync('./certificate-signing-request.pem', 'utf8')
const csr = CertificateSigningRequest.fromPem(pem)
const cert = csr.sign(issuerCert, issuerPrivateKey) // The certificate and the private key must match!!
console.log(cert)
```

### Read a certificate
```ts
import { readFileSync } from 'fs'
import { Certificate } from '@cyyynthia/jscert'

const pem = readFileSync('./certificate.pem', 'utf8')
const cert = Certificate.fromPem(pem)  // .fromAsn(asnBuffer) is also available
console.log(cert)
```

### Verify the authenticity of a certificate
**Note**: the lib will only check validity period and if the signatures match. The lib will NOT check if the
certificate you pass is trusted, and the lib will always yield `true` if the certificate is self-signed (as long
as we are withing its validity period). **You are responsible for ensuring self-signed certificates are in any form
of trust chain**.

You can check if a certificate is self-signed by checking if the `selfSigned` property is true.
```ts
import { readFileSync } from 'fs'
import { Certificate } from '@cyyynthia/jscert'

const rootCert = Certificate.fromPem(readFileSync('./root-cert.pem', 'utf8'))
const cert = Certificate.fromPem(readFileSync('./certificate.pem', 'utf8'))
console.log(cert.verify(rootCert))
```

### Decode/encode PEM
```ts
// note: for now the implementation can only read a string with a **single** PEM entity in it.
import { readFileSync } from 'fs'
import { decodePem, encodeAsn, encodePem } from '@cyyynthia/jscert'

const pem = readFileSync('./certificate-signing-request.pem', 'utf8')
console.log(decodePem(pem)) // ~> { label: 'CERTIFICATE REQUEST', asn: <Buffer ...> }

const asn = encodeAsn(...)
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
