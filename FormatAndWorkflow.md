# Commands, Workflows and Formats

## Signature Format
A NuPkg signature is an external file stored as a PEM-formatted (see below)
CMS (https://tools.ietf.org/html/rfc5652) Signed Data message. The content of the
message is a simple DER-encoded ASN.1 data structure containing important metadata:

```
SignatureFile ::= SEQUENCE {
  signatureFileVersion INTEGER      // == 1
  signatures SET OF SignatureContent
}

SignatureContent ::= SEQUENCE {
  signatureVersion INTEGER          // == 1
  contentIdentifier UTF8String      // See below
  digestAlgorithm OBJECT IDENTIFIER // Standard OID for the digest algorithm
  digest OCTET STRING               // Raw bytes of the digest
}
```
***REVIEW***: Any other content to put in the signature file? Is this superfluous? Should we just
store the digest algorithm and digest? I used ASN.1 because the CMS itself is an ASN.1 document,
we could just use a JSON/XML/whatever blob, and store that in a simple ASN.1 String or OctetString
but it seemed useful to preserve the same format as the wrapping file.

The message is then signed and the Encrypted Digest of the above data structure,
is stored along with the signature algorithm identifier, all using the standard
CMS format.

The `contentIdentifier` field identifies the content being signed. It is not a
file name, but is designed to allow for identification of individual content
being signed in the case of multiple items. When signing a NuGet Package, the
`contentIdentifier` is formatted as follows:

1. Normalize the Version to a 4-part form, where missing digits are set to 0
and the pre-release tag is present. Lowercase the entire string.
1. Normalize the ID by converting all characters to their culture-invariant
lowercase value
1. Format the string as follows "Id@Version" where Id and Version are the canonicalized
Id and Version from above.

NOTE: It is not absolutely essential that this be canonicalized, since it does
not need to be constructed to verify the signature, it can simply be read from
the signature file and then hashed to verify against the signature. The individual
members of the structure can be verified separately. Still, it seems useful to
create a well-defined format for identifying a NuGet Package

Why `SET OF` and `contentIdentifier`? I think it is valuable to make some concession
to future-proofing here by allowing a future signature format to include multiple
signed files in a single signature file (such as for embedding in a nupkg). If
the `signatureFileVersion` is set to 1 (the only version right now), the consumer
MUST only consider the first `SignatureContent`. Adding a second covered file
to the signature is NOT permitted in version 1.

## Countersignatures and Timestamps
Countersignatures are attached using the PKCS#9 Countersignature Attribute
(https://tools.ietf.org/html/rfc2985, Section 5.3.6). Only one level of
countersignature may be applied (i.e. no countersignatures of countersignatures).
However, multiple countersignatures may be applied.

During verification, if a countersignature is trusted, the entire signature will
be considered trusted, as long as the EKU (Extended Key Usage) of the signing
certificate includes the Code Signing OID.

Timestamps are supported by countersignature. If a countersignature exists and
is signed by a trusted timestamping authority, the PKCS#9 Signing Time Attribute
(https://tools.ietf.org/html/rfc2985, Section 5.3.3) indicates the time that the
signature was made. That time will be used when checking revocation lists. In order
to be considered a timestamping countersignature, the signer of the certificate
must have the Timestamping EKU value.

## Workflows

### Create a Signing Request
A signing request "sigreq" is basically an incomplete signature. It consists of
the CMS message, WITHOUT any SignerInfo structures indicating signatures. It
is created as follows

```
> kpm sigreq EntityFramework.5.0.0.nupkg
```

The result is a file `EntityFramework.5.0.0.nupkg.sigreq` containing the PEM-encoded,
incomplete CMS document

### Generating certificates
In order to sign a request, a certificate is required. There will be a command
to generate the recommended pattern of a self-signed CA and a signing cert chained
off that CA:

```
> kpm keygen
Enter your Country: US
Enter your State/Province: Washington
Enter your Locality (City/Town etc.): Redmond
Enter the name of your organization: AndrewTech Software
Please enter the name for your Root Authority Certificate: AndrewTech Root Authority
Please enter the name for your Signing Certificate: AndrewTech Code Signing

Generated the following certificates:
1. CN=AndrewTech Root Authority,O=AndrewTech Software,L=Redmond,S=Washington,C=US
2. CN=AndrewTech Code Signing,O=AndrewTech Software,L=Redmond,S=Washington,C=US

They have been stored in your CurrentUser/My certificate store, and are ready
to be used for signing. You can export them from the store using the
certificate management snap-in (http://go.microsoft.com/somethingcool)
```

The generated certificates are stored in the most appropriate place based on OS.
For Windows, this is the User certificate store. For Mac and Linux, it is yet
to be determined. If a password is needed to encrypt files on disk, the user
will be prompted for it.

### Signing a request or file
Once a certificate is available, the request can be signed.

```
> kpm sign EntityFramework.5.0.0.nupkg.sigreq
```

The user will be prompted to select certificates for signing, or can provide
them in arguments to the command. A signature is outputted to
`EntityFramework.5.0.0.nupkg.sig`

In most non-enterprise environments, the "request" model is unnecessarily complicated.
For this reason, `kpm sign` can directly sign a nupkg without using a request file.
The request file is, however, still useful in models like Microsoft where a
central code signing service is used.

### Timestamping a signature
Once a signature exists, it can be timestamped using a trusted timestamping
authority of the users choice:

```
> kpm timestamp EntityFramework.5.0.0.nupkg.sig http://timestamp.digicert.com
```

The signature file will be modified with countersignature asserting the
signing time.

### Sign and Timestamp in one command
The request generation, signing and timestamping can all be executed in a single
execution of `kpm sign` as follows:

```
> kpm sign EntityFramework.5.0.0.nupkg --timestamp-url http://timestamp.digicert.com
```

## PEM Formatting
PEM formatting is the format used by OpenSSL for encoding ASN.1 data (which is how most
cryptography-related data is formatted). It consists of an ASCII header and footer, followed by
the DER-encoded ASN.1 data written as a Base64 string. A line break is inserted every 64 characters.

The header and footer are lines of the format: "-----BEGIN THING-----"/"-----END THING-----" (where "THING"
describes the entity serialized within).

For example, the following is the PEM encoding of the github.com certificate:

```
	-----BEGIN CERTIFICATE-----
	MIIF4DCCBMigAwIBAgIQDACTENIG2+M3VTWAEY3chzANBgkqhkiG9w0BAQsFADB1
	MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
	d3cuZGlnaWNlcnQuY29tMTQwMgYDVQQDEytEaWdpQ2VydCBTSEEyIEV4dGVuZGVk
	IFZhbGlkYXRpb24gU2VydmVyIENBMB4XDTE0MDQwODAwMDAwMFoXDTE2MDQxMjEy
	MDAwMFowgfAxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRMwEQYLKwYB
	BAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwCAQITCERlbGF3YXJlMRAwDgYDVQQF
	Ewc1MTU3NTUwMRcwFQYDVQQJEw41NDggNHRoIFN0cmVldDEOMAwGA1UEERMFOTQx
	MDcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
	YW4gRnJhbmNpc2NvMRUwEwYDVQQKEwxHaXRIdWIsIEluYy4xEzARBgNVBAMTCmdp
	dGh1Yi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCx1Nw8r/3z
	Tu3BZ63myyLot+KrKPL33GJwCNEMr9YWaiGwNksXDTZjBK6/6iBRlWVm8r+5TaQM
	Kev1FbHoNbNwEJTVG1m0Jg/Wg1dZneF8Cd3gE8pNb0Obzc+HOhWnhd1mg+2TDP4r
	bTgceYiQz61YGC1R0cKj8keMbzgJubjvTJMLy4OUh+rgo7XZe5trD0P5yu6ADSin
	dvEl9ME1PPZ0rd5qM4J73P1LdqfC7vJqv6kkpl/nLnwO28N0c/p+xtjPYOs2ViG2
	wYq4JIJNeCS66R2hiqeHvmYlab++O3JuT+DkhSUIsZGJuNZ0ZXabLE9iH6H6Or6c
	JL+fyrDFwGeNAgMBAAGjggHuMIIB6jAfBgNVHSMEGDAWgBQ901Cl1qCt7vNKYApl
	0yHU+PjWDzAdBgNVHQ4EFgQUakOQfTuYFHJSlTqqKApD+FF+06YwJQYDVR0RBB4w
	HIIKZ2l0aHViLmNvbYIOd3d3LmdpdGh1Yi5jb20wDgYDVR0PAQH/BAQDAgWgMB0G
	A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjB1BgNVHR8EbjBsMDSgMqAwhi5o
	dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vc2hhMi1ldi1zZXJ2ZXItZzEuY3JsMDSg
	MqAwhi5odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vc2hhMi1ldi1zZXJ2ZXItZzEu
	Y3JsMEIGA1UdIAQ7MDkwNwYJYIZIAYb9bAIBMCowKAYIKwYBBQUHAgEWHGh0dHBz
	Oi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwgYgGCCsGAQUFBwEBBHwwejAkBggrBgEF
	BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFIGCCsGAQUFBzAChkZodHRw
	Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEyRXh0ZW5kZWRWYWxp
	ZGF0aW9uU2VydmVyQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQAD
	ggEBAG/nbcuC8++QhwnXDxUiLIz+06scipbbXRJd0XjAMbD/RciJ9wiYUhcfTEsg
	ZGpt21DXEL5+q/4vgNipSlhBaYFyGQiDm5IQTmIte0ZwQ26jUxMf4pOmI1v3kj43
	FHU7uUskQS6lPUgND5nqHkKXxv6V2qtHmssrA9YNQMEK93ga2rWDpK21mUkgLviT
	PB5sPdE7IzprOCp+Ynpf3RcFddAkXb6NqJoQRPrStMrv19C1dqUmJRwIQdhkkqev
	ff6IQDlhC8BIMKmCNK33cEYDfDWROtW7JNgBvBTwww8jO1gyug8SbGZ6bZ3k8OV8
	XX4C2NesiZcLYbc2n7B9O+63M2k=
	-----END CERTIFICATE-----
```