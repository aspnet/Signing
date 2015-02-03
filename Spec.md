# Package Signing Specification

**IMPORTANT**: This is a working specification and may change over time. Please leave your comments in the issues section of the [Signing](https://github.com/aspnet/Signing) repository.

**ALSO**: While this work is taking place in the aspnet organization on GitHub, we expect to merge it with NuGet.

The purpose of this specification is to describe a system for signing and verifying NuGet packages that meets the goals of the NuGet ecosystem. The primary goals are:

1. Allow consumers of NuGet packages to externally verify the author of a package
1. Protect consumers of NuGet packages during Package Restore to ensure they recieve a package from the same publisher as the original installation
1. Protect consumers of NuGet packages during Upgrade (or Restore with floating dependencies, like in project.json) to ensure they recieve a package from the same publisher as the original installation
1. Do not restrict other NuGet consumers (Chocolatey, Octopus Deploy, various extension galleries for other products, etc.) from implementing stricter or more detailed trust models.

This system is ***NOT*** designed to:

1. Replace [Authenticode](http://msdn.microsoft.com/en-us/library/ie/ms537359%28v=vs.85%29.aspx) as a load-time mechanism for protecting a machine from untrusted code
1. Provide verification of the identity of a package - The system only provides a guarantee that the identity has not **changed**.

## NuGet Platform vs Package Manager

The term NuGet often refers to two different concepts: 

* The NuGet Platform, which is a platform for transmitting and identifying versioned packages of artifacts
* The NuGet Package Manager for .NET, which is a set of tools that use the NuGet Platform to distribute .NET Libraries. Specifically, the Visual Studio Extension, nuget.exe, ASP.NET 5 project.json/nuget, the NuGet.org Gallery, the NuGet extension for WebMatrix, etc.

Examples of things which are built on the NuGet Platform but are **not** part of the Package Manager include Octopus Deploy (which uses NuGet packages to hold deployment artifacts) and Chocolatey (which uses NuGet packages to hold applications). These products should work to adopt as much (or as little) of the signing infrastructure as necessary to implement their own signing systems, as they choose.

The NuGet Platform will be augmented with the definitions of the infrastructure expected for signing, specifically:

* The feed protocol must be augmented to allow feeds to transmit signatures for packages (Not defined here, details still to be finalized)
* A common signature format must be defined to hold signature data (Defined here)
* A validity model must be created to describe what makes a "Valid" NuGet signature (Defined here)

Crucially, the platform does not specify the trust model to be applied when determining if a signature should be trusted. It is up to individual implementations of the platform to do this. The .NET Package Manager may choose a different trust model than Octopus Deploy, Chocolatey, or any other consumer of the NuGet platform.

The NuGet Package Manager will be augmented with a specific implementation of the signing system. Other products designed to interoperate with the Package Manager (i.e. MyGet, ProGet, etc.) should consider implementing aspects of this system, but it is designed to be entirely backwards-compatible.

## User Scenarios

The following are high-level scenarios for user interactions with the signing system. The details will be covered below.

### Viewing a signed package

Any tool which is used to view packages can choose to display the signature data to the user. For example, the Package Manager dialog may opt to display an icon indicating a signed package, along with data from the signature. Feeds which support signatures are expected to include data extracted from the signature in their feed metadata. Data which can be displayed to the user include:

* The Subject Name of the signing certificate
* The Issuer Name of the signing certificate
* The time at which the package was signed, according to the trusted timestamp
* The machine-level trust status of the certificate (i.e. is it trusted on this machine?)
* The public key hash of the issuer certificate (for comparing aginst other sources)

It is up to the individual client to determine how best to display these data.

### Installing a new package

When installing a new package via tooling (Visual Studio, command line tools, etc.), if signature data for the package is present in the feed used to install the package, that signature is retrieved along with the package. Once retrieved, the signature is checked for Validity (see below). If the signature is Valid, the package installation is allowed to continue.

When installing a package, signature data is used in two phases: Dependency Resolution and Installation. During dependency resolution, the dependencies of that package may have signer information embedded in the nuspec entry for the dependencies. For example:

```xml
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>MyPackage</id>
    <version>1.2.3</version>
    <!-- ... -->
    <dependencies>
        <dependency id="AnotherPackage" version="3.0.0" signer="... signer string ..." />
    </dependencies>
  </metadata>
</package>
```

See below for a description of the format of the `signer` attribute.

**After** a package is selected to satisfy a dependency with a `signer` attribute, the following additional checks must all succeed in order for the dependency to resolve:

1. Signature data must be available from the source of the dependency. If there is no signature provided, the resolution fails.
1. The signature data must match the data provided in all `signer` attributes that refer to that `id` (see below for more on checking signers).

**IMPORTANT:** A failure to meet these criteria should cause a rollback of the entire installation. Signature failures should **NOT** cause a different package to be selected to satisfy a dependency. All signature checks take place **AFTER** the entire graph has been resolved.

If the same package is depended-upon by multiple packages in the project, and the dependencies specify different signers, a signature conflict occurs. In ASP.Net 5, the nearest-wins dependency resolution format means that the `signer` attributes lower down the graph (further away from the dependencies specified in the project.json) can be disregarded. If there are different signers at the same level, the user must resolve the conflict. In standard NuGet, the user would always need to resolve the conflict, because NuGet has no dependency priority rules. See Conflict/Error Resolution below. In packages.config, the conflict is resolved by writing the selected signer into the packages.config (since the entire dependency graph is specified there). In project.json, the conflict is resolved by adding a top-level dependency on the conflicting package (thus masking all conflicting signers further down the graph).

### Updating an existing package

When updating an existing package, if the `signer` attribute is present in packages.config, the updated version of the package must meet the following criteria:

1. The package is signed (the source provides a signature for the package)
2. The signer string for the signature is the same as the current value encoded in packages.config

If either of these conditions fail, an error is reported. The user may be given the option, in UI contexts, to allow the update to proceed. In that case, the `signer` value for the package is updated to the value in the updated package (or removed if the updated package is unsigned).

Just as with the install scenario, the entire dependency graph must be checked, since the Update may bring in additional dependencies. In standard NuGet, `signer` values in packages which are already present in packages.config always override `signer` values in dependencies.

### Restoring an existing package

When restoring an existing package, if the `signer` attribute is present in packages.config, the downloaded package must meet the same criteria as in the Update scenario above. However, if it fails to meet this conditions, the user is not given the option to update the signer data since the package was not expected to change in this scenario. The user may opt to uninstall the old package and install a new copy with a different signature.

### Conflict/Error Resolution

When a signature conflict occurs, during an interactive operation (see below), the user is prompted to select the signature they wish to accept and the signature is written into the appropriate location (packages.config/project.json). In a non-interactive operation (see below), an error is reported (as appropriate to the UI) and the command fails (returning a non-zero exit code or other error indicator).

Interactive Operations are any operations that are directly initiated by a user during an interactive user session. For example:

* Clicking Install/Upgrade/Restore in the NuGet Dialog
* Running a command-line application to install/upgrade/restore packages (`nuget install`, `nuget restore`, etc.)

Non-Interactive Operations are any operations that occur due to a non-user-initiated or indirectly-initiated action. For example:

* Running a command-line application during a script - The error causes the application to exit with a non-zero code and writes to the standard error stream.
* Running a background process in Visual Studio - The error is indicated on the Packages node in Solution Explorer
* Running during a build process in Visual Studio - The error is reported as a build error.
* Running integrated into other build processes (MSBuild, TeamCity, etc) - The error is reported as a build error

## Signature Format

The signature is stored as a separate file from the file being signed. It is a Base64 encoding of the [DER encoding](http://en.wikipedia.org/wiki/X.690#DER_encoding) of a [CMS SignedData](https://tools.ietf.org/html/rfc5652#section-5.1) structure. The Base64 encoded bytes are surrounded by a header and footer as below (based on the PEM format used by OpenSSL). The result is stored as a UTF-8 text file and given the file extension `.sig`.

```
-----BEGIN FILE SIGNATURE-----
<<Base64-encoded text>>
-----END FILE SIGNATURE-----
```

### Signature Payload

To generate a signature, a DER-encoded ASN.1 data structure is constructed from the target file based on the following ASN.1 structure:

```
SignaturePayload ::= SEQUENCE {
    version             INTEGER { v1(1) },
    contentIdentifier   UTF8String,
    contentDigest       DigestValue }
DigestValue ::= SEQUENCE  {
    digestAlgorithm     OBJECT IDENTIFIER
    digest              OCTET STRING }
```

The `version` field must ALWAYS be set to `1` when adhering to this version of the specification.

The `contentIdentifier` must be set to the name of the file being signed, with no path information. For example, if the file `C:\Foo\Bar.txt` is being signed, the `contentIdentifier` should be set to `Bar.txt`.

The `digestAlgorithm` must be set to the OID for the `sha256` digest algorithm (`2.16.840.1.101.3.4.2.1`) when `version` is set to 1. No other algorithms are supported by version 1 of this signature format. Future algorithms will be supported by incrementing the version number. Thus, this is mostly an informative field and the client is not required to process it when `version` is set to `1`.

The `digest` must be set to the raw bytes of the SHA256 hash of the entire file referenced by `contentIdentifier`. No canonicalization is performed, the file is hashed exactly as-is.

When signing NuGet Packages, the signature must be calculated over the entire compressed `nupkg` file. As a result, recompression **will** break the signature. Some users recompress packages after using `nuget pack` in order to achieve better compression; it is **essential** that signing happen **after** recompression in these cases. Also, adding or removing files from the package will break the signature, this is by design in order to prevent tampering. Finally, there is no guarantee that compressing identical files multiple times will result in an identical ZIP file.

### Signing

To sign the file, the payload above is used as the `eContent` value of a [CMS EncapsulatedContentInfo](https://tools.ietf.org/html/rfc5652#section-5.2) structure, with the `eContentType` value set to `id-data` (`1.2.840.113549.1.7.1`). The payload is then signed with a signing certificate specified by the user and the necessary [CMS SignerInfo](https://tools.ietf.org/html/rfc5652#section-5.3) is added to the file.

The [CMS Signing Time](https://tools.ietf.org/html/rfc5652#section-11.3) authenticated attribute must be applied to the signature before signing. However, the value of this attribute should not be used as a trusted source of time, it is purely for informative purposes.

### Trusted Timestamps

Signatures can include Trusted Timestamps issued by a trusted timestamping authority. The timestamp allows the signature to live longer than the validity of the certificate. If a timestamp is present, it must be encoded as a "signature time-stamp" Unauthenticated Attribute of the SignerInfo, as defined in the [CAdES-T specification](https://tools.ietf.org/html/rfc5126#section-6.1).

The trusted timestamp is generated by submitting the `signature` field from the [CMS SignerInfo](https://tools.ietf.org/html/rfc5652#section-5.3) to a [RFC 3161](https://tools.ietf.org/html/rfc3161)-compliant timestamping service of the user's selection. A set of default timestamping services may be provided by client tools. The resulting `TimeStampToken` value is stored as a raw `OCTET STRING` value for the signature time-stamp field described in CAdES-T.

Trusted timestamping is generally a free service provided by code-signing certificate issuers. However, since it is an external dependency, signatures are not required to have trusted timestamps. However, signatures without trusted timestamps will become permenantly invalid when the certificate that was used to generate the signature expires or is revoked, since there is no guarantee the signature was made prior to the certificate expiration/revocation.

### Similarity to Authenticode

This format is similar to the [Authenticode](http://msdn.microsoft.com/en-us/library/ie/ms537359%28v=vs.85%29.aspx) system developed by Microsoft, but there are a few minor differences:

1. The timestamp is not stored as a Countersignature. Instead, we used the "signature time-stamp" attribute of the newer [CAdES-T specification](http://www.ietf.org/rfc/rfc5126.txt).
1. The payload is custom to our system
1. The signature is stored externally to the file covered by the signature

**This system is NOT intended to replace Authenticode.** It is for NuGet Package transmission only and Authenticode (or similar models on other platforms) will still be used to protect the loading of the artifacts WITHIN NuGet packages.

**This specification provides no mechanism for verifying package signatures at application run-time**. The signature is intended to be disregarded once the package is down on disk.

## Signature Verification and Trust

### Verification

A NuGet Package Signature must satisfy the following requirements in order to be considered `valid`. This does **NOT** imply that the signature is `trusted`, that is up to the individual consumer (see below). All consumers of the NuGet Platform should use this verification model unless it is absolutely necessary to deviate.

1. The signature is a well-formed [CMS](https://tools.ietf.org/html/rfc5652) message in PEM format
1. The `version` field in the payload specified above must be set to `1`.
1. Only a single [CMS SignerInfo](https://tools.ietf.org/html/rfc5652#section-5.3) structure is present.
1. The SignerInfo contains the [Signing Time](https://tools.ietf.org/html/rfc5652#section-11.3) attribute
1. All certificates necesary to build certificate chains for ALL certificates used in the signature file (including the timestamp signer) must be embedded. Consumers must **never** need to use the machine/user-level certificate store to resolve a valid chain.
1. The provided certificates must resolve to a single chain with no cross-signing or bridges.
1. All certificates in the chain must meet basic key usage and extended key usage requirements:
    1. Intermediate and Root certificates must have the `keyCertSign` bit in their `keyUsage` field set and the `cA` flag in their basic constraints set.
    1. If a certificate in the chain contains a `pathLenConstraint`, it must be verified against the depth of the chain below that certificate.
1. The `encryptedDigest` value in the [CMS SignerInfo](https://tools.ietf.org/html/rfc5652#section-5.3), once decrypted by the public key of the signer certificate, must validate correctly against the message digest as per the [CMS specification](https://tools.ietf.org/html/rfc5652#section-5.4).
1. The `digest` value of the Payload must match the `sha256` digest of the file identified by `contentIdentifier`.
1. If a trusted timestamp is applied, the certificate used to sign it must chain to a root that is already trusted by the operating system (i.e. a real, root CA).
1. The certificate used to produce the signature must be within it's validity period according to one of the following times (in priority order; if the trusted timestamp is available, it MUST be used):
    1. The UTC time encoded in a trusted timestamp applied to the signature, OR if (and ONLY if) no trusted timestamp is present...
    1. The Current UTC time according to the system clock on the machine performing the verification.

Additionally, when the signed package contains code for execution by a computer (i.e. in the case of the NuGet Package Manager), the following requires must also be met. Other usages of NuGet packages (i.e. in environment where it is being used to deliver non-executable data, for example) may choose to omit these requirements or place their own EKU requirements on the certificates used to sign packages.

1. The certificate used to generate the signature must have the "Code Signing" Extended Key Usage value (`1.3.6.1.5.5.7.3.3`) OR all certificates in the chain must have NO Extended Key Usage values
1. If EKUs are present in Intermediate and Root certificates, all of them must contain the "Code Signing" value (`1.3.6.1.5.5.7.3.3`) or the special "anyExtendedKeyUsage" value (`2.5.29.37.0`).

NuGet Servers may choose to evaluate signatures they receive as `valid` before accepting them.

### Trust

Once a signature is deemed `valid`, it can be evaluated for trust. The specific trust model used depends upon the context in which the NuGet Platform is being used. This section defines how the NuGet Package Manager for .NET will evaluate trust. Other contexts may choose to use the same model, or their own model.

#### First Install

During initial installation of a package into a project which does not already have a version of the package installed, limited trust checking is performed:

1. If any certificate in the chain is known by the operating system to be revoked (via revocation data distributed via OS updates, for example), the package is considered `untrusted`.
1. If any certificate in the chain define CRL Distribution Points or OCSP Responders, those are checked:
    1. If no valid CRL/OCSP response is retrieved, the package is considered `untrusted`. If a CRL/OCSP response cannot be retrieved due to a lack of network connectivity, the package should be considered `untrusted`. Since the trust check is only performed when retrieving a package from remote sources, it is unlikely that the package will be installed while the matching CRL/OCSP services are unavailable. A user override could possibly be provided for this behavior. [OCSP Stapling](http://en.wikipedia.org/wiki/OCSP_stapling) could be used as a way to reduce this issue by providing an OCSP response along with the package.
    1. If the CRL/OCSP response is not signed by a certificate that chains to the same root, or is not authorized to issue CRL/OCSP responses (according to the CRL/OCSP specifications, details TBD), the package is considered `untrusted`
1. If the certificate is not known by the OS to be revoked and contained no CRL/OCSP identifiers, or successful CRL/OCSP responses can be located that indicate the certificate is valid at the time of signing (according to the trusted timestamper), the package is considered `trusted`

So, if a certificate chain specifies CRL/OCSP indicators and those return successful responses, OR if the certificate chain has no CRL/OCSP indicators, the package is considered `trusted` regardless of it's origin or certificate chain. Other NuGet consumers will have the opportunity to change this initial trust model, and we may consider a system in the future where the NuGet Package Manager may provide project-level (or higher) settings to adjust this trust model.

When a signed package installed into a project for the first time, the following data is recorded in packages.config (or project.json, as appropriate to the project type, specifics are below):

1. The SHA256 hash of the Public Key of the Root certificate in the signing certificate chain.
1. The Common Name of the End certificate in the signing certificate chain

#### Restore/Update

In future downloads of the package (either from Package Restore via VS or nuget.exe, or when installing updated versions of the package), the data above are recalculated based on the signature provided during download. If a signature cannot be retrieved from the package source, but the packages.config/project.json indicates that the package should be signed, the package is treated as untrusted and an error is reported. The same trust evaluation as the First Install process above is performed, but an additional check is added:

If the recalculated data match the data recorded in packages.config/project.json, the package is considered `trusted` and the download completes. If the recalculated data do not match the data recorded in packages.config/project.json, the package is considered `untrusted`, the downloaded file is deleted and an error is raised (see User Scenarios above for details on error reporting).

The user may, if they choose, either update the data in their packages.config/project.json or uninstall the package and install the new one.

## NuGet Changes

### Storage and transmission of the signature

**TODO**: The server-side portion of this still needs to be clarified a bit, but that can come once we've solidified the full workflow.

The signature file will be transmitted to the server along with the package. The signature file can also be transmitted independently for an existing package. The server should verify the following, but is not expected to do so:

1. The signature is `valid` as specfied above, using the package file it is associated with.
1. The package file does not already have a signature stored for it in the system. (Multiple signatures for a package are not currently supported)

When package metadata is retrieved for a package, it will include a URL that can be used to download the signature file for a package. The client will download this signature along with the package and perform the necessary verification and trust checking using that.

### packages.config

In order to support this feature, changes must be made to the listing of installed packages for a particular project. In NuGet this is stored in packages.config. In order to support the Trust model above, data must be added to these files. When installing a signed package into a packages.config, the package node will look something like this:

```xml
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="6.0.4" targetFramework="net45" signer="commonName=James Newton-King,rootPublicKey=sha256:YXNkZmFzZGZhc2Rm..." />
</packages>
```

### project.json

In ASP.NET 5, a `project.json` file is used in place of packages.config. When signer data needs to be encoded in this file, it is encoded as follows:

```json
{
    "dependencies": {
        "Newtonsoft.Json": {
            "version": "6.0.4",
            "signer": "commonName=James Newton-King,rootPublicKey=sha256:YXNkZmFzZGZhc2Rm..."
        }
    }
}
```

### Signer Identity String

The `signer` strings in the previous examples use a format specific to this system, designed to be mostly opaque to users and easily copied around into command lines, etc. The format is encoded in the following format:

```
commonName=[commonName],rootPublicKey=[rootPublicKey]
```

Where `commonName` and `rootPublicKey` are encoded using the rules defined in [RFC4514 Section 2.4](https://tools.ietf.org/html/rfc4514#section-2.4). Please note that while the signer string resembles an X.500 Distinguished Name, it is **NOT** one. The `commonName` field **may not** be abbreviated, and the `rootPublicKey` is not part of an X.500 Distinguished Name.

The `commonName` field contains the subject common name of the End certificate in the signing chain, and the `rootPublicKey` contains a Base64-encoded hash of the Public Key of the Root certificate in the signing certificate chain, with the name of the hash algorithm prepended and a colon (":") separating the two. In theory, the signer string can be extended or modified to use other fields, using a format similar to the string encoding of X.500 Distinguished Names.

## Workflows

### 1. Key Generation

To generate a signing key, the publisher must run the `keygen` command. That command will prompt them to enter various data describing them as a publisher and will then produce two certificates (the text "&lt;ENTER&gt;" indicates where the user presses the ENTER key in the example).

```
> nuget keygen
We need some information describing you to incorporate into your certificates.
This data will help users determine who you are. You may leave all but the 
"Common Name" field blank if you wish, but providing more data will help users

Country Name (2 letter code, e.g. 'US'): US<ENTER>
State or Province Name (full name): Washington<ENTER>
Locality Name (city or town): Redmond<ENTER>
Organization Name: Fabrikam<ENTER>

Enter the name for your "Root" certificate, or press enter to accept the default of
"Fabrikam NuGet Signing Root Authority"
Root Common Name:<ENTER>

Enter the name for your signing certificate, or press enter to accept the default of
"Fabrikam NuGet Signing Certificate 2014"
Signer Common Name:<ENTER>

Generated certificates:
 fabrikam-nuget-signing-root-authority.cer
 fabrikam-nuget-signing-certificate-2014.cer

Enter a passphrase to protect your Root Certificate private key: *****************
Exported root certificate private key to: C:\Users\johndoe\Documents\fabrikam-code-siging-root-authority.pfx
```

On Mac and Windows, the signing certificate would be stored in the Keychain/Certificate Store. It could even be marked non-exportable for additional security, since the root certificate can always be used to generate a new signing certificate. On Linux, the signing certificate would have to be exported as well, and a passphrase would be used for that purpose as well. We would always store the root certificate private key in a specific location ("~/" on Mac/Linux, User documents folder on Windows) in order to reduce the risk of unintentionally uploading the private key to a public source control system. We would also always require a strong passphrase (specific "strength" TBD) for the private key.

The generated certificates will have the following characteristics:

1. BOTH Certificates:
    1. `sha256RSA` signature algorithm
    1. 4096-bit RSA key
1. Root Certificate
    1. Extended Key Usage: Code Signing
    1. Valid for 20 years (10 years?)
    1. Basic Key Usage: Digital Signature, Certificate Signing, CRL Signing, Off-line CRL Signing
    1. Self-signed
1. Signer Certificate
    1. Extended Key Usage: Code Signing
    1. Valid for 2 years (1 year?)
    1. Basic Key Usage: Digital Signature
    1. Issued and signed by the Root Certificate

This is not designed to be a general-purpose certificate generation tool, so it is not possible to generate a certificate with different characteristics (key sizes, signature algorithms, EKUs, etc.). Users should use a general-purpose certificate generation tool like `certreq.exe` or `openssl` if they wish to create different certificate.

### 2. Signing

To sign a package, the publisher uses the `sign` command. The command requires no interactive prompting, given
enough arguments, so it is suitable to be used on Build Servers. The command takes the file to sign and information about the certificate to use for signing as arguments. The result is a `.sig` file in the format described above. If any of the keys needed for signing are secured by passwords, the user will be prompted interactively for them. The user can also provide passwords as command-line arguments for automated build servers. The `sign` command will also provide options to use certificates stored in machine/user-level certificate stores (depending upon the platform).

The user can also provide the URL to a timestamping server to perform trusted timestamping. If they do provide this URL, the timestamp is applied immediately after signing.

### 3. Timestamping

The publisher may timestamp an existing signature separately from the signing process. For example, the signing may be performed on a machine without internet access, and thus the signing process may be unable to reach the timestamping authority. To do this, a publisher simply provides the signature file and a URL to a timestamping authority.

### 4. Package Installation

During install, a user may optionally provide the `signer` string indicated above in order to provide an initial trust basis:

```
> nuget install Newtonsoft.Json --signer "commonName=James Newton-King,rootPublicKey=sha256:YXNkZmFzZGZhc2Rm..."
```

Or in the NuGet PowerShell console:

```
> Install-Package Newtonsoft.Json -Signer "commonName=James Newton-King,rootPublicKey=sha256:YXNkZmFzZGZhc2Rm..."
```

In these cases, the initial install behaves as though it were an Upgrade or Restore, using the specified Signer string as the "expected" signer value.

### 5. Lost keys

If a publisher loses their root certificate private key and is unable to sign future packages, the only recourse for the future is something like the following:

1. If possible, revoke the lost certificate chain
1. Produce a new signing key set
1. Sign ALL past and future packages with that new key set (The gallery may want to allow multiple signatures for this purpose, or for the user to replace the signature).
1. Existing users will, unfortunately, have to uninstall and reinstall to use the new key. However, this will be a one-time operation and those users will have full access to all past and future versions of the package.

This situation is the main reason the Package Upgrade process allows a user to accept a change in signing key.

### 6. Stolen keys

If any of a publisher's keys are stolen, they will have to revoke the corresponding certificate. If the certificates come from a standard CA, that authority will have a process for revoking them. If they are self-generated, it will be up to the user to have embedded the necessary CRL/OCSP distribution points to allow revocation. Since a CRL is a static file, it is relatively easy to host. We can provide some guidance on setting up a CRL infrastructure.
