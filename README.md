Usage: `./check_certificates.sh -f <file> [-p <password>]`  
Supported file types: `.pfx`, `.pem`, `.csr`, `.key`

Following checks are implemented:
- Weak algorithms:
  - md2
  - md4
  - md5
  - sha1
  - sha1WithRSAEncryption
  - ecdsa-with-SHA1
  - DSA-SHA1
  - RC4
- key length < 2048 bits
- certificate chain validity
- missing encryption of the private key
- weak MAC algorithm
