# NuGet Package Signing

## Terms
Most of these terms will likely be familiar, but just to be clear:

1. "Encrypted Digest" - Basically the core of the signature. A signature is a digest (or hash) of the target data that has been encrypted with the Private Key matching a particular key pair.
1. "Self-Issued" - A Signing Certificate that is issued by a Self-Signed Root Certificate, that is not normally trusted by the system. This differs from a Self-Signed certificate in that the Signing Certificate follows the normal pattern of being Issued by a Root.
1. "Countersignature" - A signature of a signature. A countersignature is made by signing the encrypted digest portion of an existing signature. This technique can be used for Timestamping, as well as in a future scenario around Enterprise trust
1. "Trusted Timestamp" - A countersignature applied by a Trusted Timestamping Authority. A trusted timestamp is applied by sending the encrypted digest of the existing signature up to a timestamping authority and they send back a signature of that data, as well as a signed timestamp. This proves that the signature existed at a particular point in time (according to the authority, which must be trusted)

## Core Scenario
Ensure the identity of downloaded/upgraded packages matches the identity provided during initial install

### Future Scenario
Allow Enterprises to restrict package installation to trusted publishers. This will also include an ability
for Enterprises to apply "countersignatures" (signatures of signatures) that can "endorse" the use of a specific
package, even if the signature is not normally trusted (i.e. self-issued certificates)

## Usage Process
During initial installation of a package, if a signature is present, the signature will be verified against the package. At this point, as long as the signature is valid (digest values match, within validity period, etc.), the signature will be considered trusted for this package. The signature will contain metadata indicating a certificate in the signing chain to be "pinned". This certificate's public key will be hashed and embedded in project.json, along with the Subject Common Name of the signing certificate itself. For example, given Newtonsoft.Json, signed by a subject certificate with Subject Common Name "James Newton-King", the project.json would contain the following after installation:

```json
{
	"dependencies": {
		"Newtonsoft.Json": {
			"version": "5.0.0",
			"signer": {
				"name": "James Newton-King",
				"issuerKeyIdentifier": "sha256:nwcerHnlFrtIAXlwRmsNdc..."
			}
		}
	}
}
```