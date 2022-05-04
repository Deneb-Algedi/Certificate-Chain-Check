# Certificate-Chain-Check


## Table of contents
- [Description](#description)
- [Design and Flaw](#design-and-flaw)
- [Requirements](#requirements)
- [How to run](#how-to-run)
- [References](#references)

## Description
"TLS secures network data by encrypting HTTP traffic. A key part of this process is validating the certificates, which prevents malicious actors from posing as trusted websites (as long as we trust the right people to begin with)."

As part of an assignment, I wrote my own X.509 certificate-chain validation program.

## Design and Flaw

### Design
In order to check the certificate chain, I first created a trusted certificate store by adding each of the root certificates on my system. Then, for each certificate chain I would traverse it from intermediate to leaf and verify the certificate with the store and check if it was expired. Additionally, for the leaf certificate, I compared the target domain with the certificate Common Name if these did not match I would then make the comparison against all Subject Alternate Name. If the certificates were valid they’d be added to the store.

### Flaw
The store created does not have a revocation list. Therefore, if there were the case that the private key of a company website’s SSL certificate was compromised this certificate should be revoked and no longer trusted, just like an expired certificate

## Requirements


## How to run

```sh
python3 certificateChainCheck.py google.com
```

```sh
python3 certificateChainCheck.py www.youtube.com
```


## References


