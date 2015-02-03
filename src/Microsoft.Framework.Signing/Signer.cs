using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Framework.Logging;
using Microsoft.Framework.Signing.Native;

namespace Microsoft.Framework.Signing
{
    /// <summary>
    /// Creates and manages file signatures
    /// </summary>
    public class Signer
    {
        private ILogger _logger;

        public Signer() : this(NullLoggerFactory.Instance) { }
        public Signer(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.Create<Signer>();
        }

        /// <summary>
        /// Prepares an unsigned signature request for the specified file, using
        /// the default digest algorithm (SHA-256, see <see cref="Signature.DefaultDigestAlgorithmName"/>).
        /// </summary>
        /// <param name="fileName">The name of the file to create the signature for</param>
        public Signature Prepare(string fileName)
        {
            return Prepare(fileName, Signature.DefaultDigestAlgorithmName);
        }

        /// <summary>
        /// Prepares an unsigned signature request for the specified bytes, using
        /// the default digest algorithm (SHA-256, see <see cref="Signature.DefaultDigestAlgorithmName"/>)
        /// and the specified content identifier.
        /// </summary>
        /// <param name="contentIdentifier">
        /// The value to use as the content identifier. This is usually a filename, when
        /// the content begin signed is a file. If the content being signed is not a file,
        /// any short descriptive string can be used here.
        /// </param>
        /// <param name="input">The data to sign</param>
        public Signature Prepare(string contentIdentifier, byte[] input)
        {
            return Prepare(contentIdentifier, input, Signature.DefaultDigestAlgorithmName);
        }

        /// <summary>
        /// Prepares an unsigned signature request for the specified data, using
        /// the default digest algorithm (SHA-256, see <see cref="Signature.DefaultDigestAlgorithmName"/>)
        /// and the specified content identifier.
        /// </summary>
        /// <param name="contentIdentifier">
        /// The value to use as the content identifier. This is usually a filename, when
        /// the content begin signed is a file. If the content being signed is not a file,
        /// any short descriptive string can be used here.
        /// </param>
        /// <param name="input">The data to sign</param>
        public Signature Prepare(string contentIdentifier, Stream input)
        {
            return Prepare(Signature.DefaultDigestAlgorithmName);
        }

        /// <summary>
        /// Prepares an unsigned signature request for the specified file, using
        /// the specified digest algorithm
        /// </summary>
        /// <param name="fileName">The name of the file to create the signature for</param>
        /// <param name="digestAlgorithm">The name of the algorithm to use for the signature</param>
        public Signature Prepare(string fileName, string digestAlgorithm)
        {
            using (var stream = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                return Prepare(Path.GetFileName(fileName), stream, digestAlgorithm);
            }
        }

        /// <summary>
        /// Prepares an unsigned signature request for the specified bytes, using
        /// the specified digest algorithm and the specified content identifier.
        /// </summary>
        /// <param name="contentIdentifier">
        /// The value to use as the content identifier. This is usually a filename, when
        /// the content begin signed is a file. If the content being signed is not a file,
        /// any short descriptive string can be used here.
        /// </param>
        /// <param name="input">The data to sign</param>
        /// <param name="digestAlgorithm">The name of the algorithm to use for the signature</param>
        public Signature Prepare(string contentIdentifier, byte[] input, string digestAlgorithm)
        {
            using (var stream = new MemoryStream(input))
            {
                return Prepare(contentIdentifier, stream, digestAlgorithm);
            }
        }

        /// <summary>
        /// Prepares an unsigned signature request for the specified data, using
        /// the specified digest algorithm and the specified content identifier.
        /// </summary>
        /// <param name="contentIdentifier">
        /// The value to use as the content identifier. This is usually a filename, when
        /// the content begin signed is a file. If the content being signed is not a file,
        /// any short descriptive string can be used here.
        /// </param>
        /// <param name="input">The data to sign</param>
        /// <param name="digestAlgorithm">The name of the algorithm to use for the signature</param>
        public Signature Prepare(string contentIdentifier, Stream input, string digestAlgorithm)
        {
            var algorithm = HashAlgorithm.Create(digestAlgorithm);
            var oid = CryptoConfig.MapNameToOID(digestAlgorithm);

            // TODO: Asyncify this by reading from the stream asyncly and using Transform(Final)Block APIs on HashAlgorithm
            var digest = algorithm.ComputeHash(input);
            var payload = new SignaturePayload(contentIdentifier, new Oid(oid), digest);
            return new Signature(payload);
        }

        /// <summary>
        /// Signs the provided signature request with the specified certificate. Uses only the Operating
        /// System certificate store (if present) to build the full chain for the signing cert.
        /// </summary>
        /// <param name="sig">The <see cref="Signature"/> object containing the request to apply a signature to.</param>
        /// <param name="signingCert">The certificate and private key to sign the document with</param>
        public void Sign(Signature sig, X509Certificate2 signingCert)
        {
            Sign(sig, signingCert, null, null);
        }

        /// <summary>
        /// Signs the signature request with the specified certificate,
        /// and uses the provided additional certificates (along with the Operating System certificate
        /// store, if present) to build the full chain for the signing cert and embed that in the
        /// signature.
        /// </summary>
        /// <param name="sig">The <see cref="Signature"/> object containing the request to apply a signature to.</param>
        /// <param name="signingCert">The certificate and private key to sign the document with</param>
        /// <param name="chainBuildingCertificates">Additional certificates to use when building the chain to embed</param>
        public void Sign(Signature sig, X509Certificate2 signingCert, X509Certificate2Collection chainBuildingCertificates)
        {
            Sign(sig, signingCert, chainBuildingCertificates, null);
        }

        /// <summary>
        /// Signs the signature request with the specified certificate, embeds all the specified additional certificates
        /// in the signature, and uses the provided additional certificates (along with the Operating
        /// System certificate store, if present) to build the full chain for the signing cert and
        /// embed that in the signature.
        /// </summary>
        /// <param name="sig">The <see cref="Signature"/> object containing the request to apply a signature to.</param>
        /// <param name="signingCert">The certificate and private key to sign the document with</param>
        /// <param name="chainBuildingCertificates">Additional certificates to use when building the chain to embed</param>
        /// <param name="certificatesToEmbed">Additional certificates to add to the signature</param>
        public void Sign(Signature sig, X509Certificate2 signingCert, X509Certificate2Collection chainBuildingCertificates, X509Certificate2Collection certificatesToEmbed)
        {
            // TODO: Investigate asyncifying this. The managed signing APIs are all synchronous, but maybe P/Invoke can help?

            if (sig.IsSigned)
            {
                throw new InvalidOperationException("A signature already exists");
            }

            // Create the content info
            var content = new ContentInfo(sig.Payload.Encode());

            // Create the signer
            var signer = new CmsSigner(SubjectIdentifierType.SubjectKeyIdentifier, signingCert);
            var signingTime = new Pkcs9SigningTime(DateTime.UtcNow);
            signer.SignedAttributes.Add(
                new CryptographicAttributeObject(
                    signingTime.Oid,
                    new AsnEncodedDataCollection(signingTime)));

            // We do want the whole chain in the file, but we can't control how
            // CmsSigner builds the chain and add our additional certificates.
            // So, we tell it not to worry and we manually build the chain and
            // add it to the signer.
            signer.IncludeOption = X509IncludeOption.EndCertOnly;

            // Embed all the certificates in the CMS
            var chain = new X509Chain();
            if (chainBuildingCertificates != null)
            {
                chain.ChainPolicy.ExtraStore.AddRange(chainBuildingCertificates);
            }
            chain.Build(signingCert);
            foreach (var element in chain.ChainElements)
            {
                // Don't re-embed the signing certificate!
                if (!Equals(element.Certificate, signingCert))
                {
                    signer.Certificates.Add(element.Certificate);
                }
            }
            if (certificatesToEmbed != null)
            {
                signer.Certificates.AddRange(certificatesToEmbed);
            }

            // Create the message and sign it
            // Use a local variable so that if the signature fails to compute, this object
            // remains in a "good" state.
            var cms = new SignedCms(content);
            cms.ComputeSignature(signer);

            SetSignature(sig, cms);
        }

        /// <summary>
        /// Applies an RFC 3161 Trusted Timestamp (http://tools.ietf.org/html/rfc3161) to the provided signature using the
        /// provided timestamping authority.
        /// </summary>
        /// <param name="sig">The signature to apply the timestamp to</param>
        /// <param name="timestampingAuthority">The URL to an RFC 3161 timestamping authority</param>
        public void Timestamp(Signature sig, Uri timestampingAuthority)
        {
            Timestamp(sig, timestampingAuthority, Signature.DefaultDigestAlgorithmName);
        }

        /// <summary>
        /// Applies an RFC 3161 Trusted Timestamp (http://tools.ietf.org/html/rfc3161) to the provided signature using the
        /// provided timestamping authority. Requests that the authority use the provided digest algorithm to timestamp the data
        /// </summary>
        /// <param name="sig">The signature to apply the timestamp to</param>
        /// <param name="timestampingAuthority">The URL to an RFC 3161 timestamping authority</param>
        /// <param name="requestedDigestAlgorithmName">The name (as supported by <see cref="CryptoConfig.MapNameToOID(string)"/>) of the digest algorithm to request</param>
        public void Timestamp(Signature sig, Uri timestampingAuthority, string requestedDigestAlgorithmName)
        {
            // TODO: Investigate asyncifying this. The timestamping APIs all appear to be synchronous.

            var digestAlgorithmOid = CryptoConfig.MapNameToOID(requestedDigestAlgorithmName);
            if (digestAlgorithmOid == null)
            {
                throw new InvalidOperationException("Unknown digest algorithm: " + requestedDigestAlgorithmName);
            }

            // Get the encrypted digest to timestamp
            byte[] digest;
            using (var cms = NativeCms.Decode(sig.Encode(), detached: false))
            {
                digest = cms.GetEncryptedDigest();
            }

            // Request a timestamp and add it to the signature as an unsigned attribute
            var timestamp = RFC3161.RequestTimestamp(digest, digestAlgorithmOid, timestampingAuthority);

            // Build the certificate chain locally to ensure we store the whole thing
            var chain = new X509Chain();
            if (!chain.Build(timestamp.SignerInfos[0].Certificate))
            {
                throw new InvalidOperationException("Unable to build certificate chain for timestamp!");
            }

            // Reopen the timestamp as a native cms so we can modify it
            byte[] rawTimestamp;
            using (var cms = NativeCms.Decode(timestamp.Encode(), detached: false))
            {
                cms.AddCertificates(chain.ChainElements
                    .Cast<X509ChainElement>()
                    .Where(c => !timestamp.Certificates.Contains(c.Certificate))
                    .Select(c => c.Certificate.Export(X509ContentType.Cert)));
                rawTimestamp = cms.Encode();
            }

            // Reopen the signature as a native cms so we can modify it
            SignedCms newSignature = new SignedCms();
            using (var cms = NativeCms.Decode(sig.Encode(), detached: false))
            {
                cms.AddTimestamp(rawTimestamp);
                var newSig = cms.Encode();
                newSignature.Decode(newSig);
            }

            // Reset the signature
            SetSignature(sig, newSignature);
        }

        private void SetSignature(Signature sig, SignedCms cms)
        {
            sig.SetSignature(cms);

            var signerInfo = cms.SignerInfos.Cast<SignerInfo>().FirstOrDefault();
            if (signerInfo != null)
            {
                // Check for a timestamper
                var attr = signerInfo
                    .UnsignedAttributes
                    .Cast<CryptographicAttributeObject>()
                    .FirstOrDefault(c => c.Oid.Value.Equals(Constants.SignatureTimeStampTokenAttributeOid.Value, StringComparison.OrdinalIgnoreCase));
                if (attr != null && attr.Values.Count > 0)
                {
                    var timestamp = new SignedCms();
                    timestamp.Decode(attr.Values[0].RawData);

                    // Check the timestamp against the data
                    var token = RFC3161.VerifyTimestamp(sig.EncryptedDigest, timestamp);
                    sig.SetTimestamp(token);
                }
            }
        }
    }
}