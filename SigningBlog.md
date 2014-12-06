# Package Signing

## Goals
Focus: Protect the _transmission_ of NuGet packages from Author to User's Local Machine.

1. Protect users from compromised NuGet servers. What if someone took control of NuGet.org?
1. Protect package restore to ensure that the package retrieved on machine A is from the same publisher as the one installed on machine B
1. Protect upgrades to ensure that v2 of a package was published by the same publisher as v1
1. Allow other NuGet consumers to add trust models to support initial install

**Non-Goal**: Protect users during first-time install - We don't feel confident that we can do that in the core platform.
**Non-Goal**: Ensure the integrity of packages at runtime - Authenticode should be used to ensure the integrity of DLLs and other files loaded at runtime.

## Implementation
Package Authors can produce a signature of a package using the [PKCS#7/CMS format](https://tools.ietf.org/html/rfc2315). The entire ZIP file of the package is used as detached content in a SignedData structure as defined by that format. The result is signed by a Private Key associated with an X.509 Certificate. The certificate, and it's entire chain of issuers, is embedded in the SignedData structure.

## Protection from a Compromised Server
If NuGet.org is compromised at a later