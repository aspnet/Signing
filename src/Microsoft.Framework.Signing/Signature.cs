using System;
using System.Linq;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Text;
using System.Security.Cryptography.Pkcs;
using System.Collections.Generic;

namespace PackageSigning
{
    public class Signature
    {
        public static readonly string DefaultHashAlgorithmName = "sha256";
        public static readonly HashAlgorithm DefaultHashAlgorithm = (HashAlgorithm)CryptoConfig.CreateFromName(DefaultHashAlgorithmName);
        private static readonly string Sha256Oid = "2.16.840.1.101.3.4.2.1";
        private static readonly string CodeSigningEKUOid = "1.3.6.1.5.5.7.3.3";

        private SignedCms _signedCms;

        /// <summary>
        /// Gets information about the certificate that created the signature
        /// </summary>
        public Signer Signer { get; private set; }

        /// <summary>
        /// Gets a list of <see cref="Signer"/> objects representing other certificates that countersigned the data.
        /// </summary>
        public IEnumerable<Signer> CounterSigners { get; private set; }

        /// <summary>
        /// Gets a trusted timestamp indicating when the signature was generated.
        /// </summary>
        /// <remarks>
        /// If this value is null, a trusted timestamp was not embedded in the signature and 
        /// the current system time should be used during verification.
        /// </remarks>
        public DateTime? TimestampUtc { get; private set; }

        private Signature(SignedCms signedCms)
        {
            _signedCms = signedCms;

            // Read the signer
            var signerInfo = _signedCms.SignerInfos.Cast<SignerInfo>().FirstOrDefault();
            Signer = Signer.FromSignerInfo(signerInfo, _signedCms.Certificates);
        }

        /// <summary>
        /// Writes the signature to the specified file.
        /// </summary>
        /// <param name="fileName">The name of the file to write the signature to.</param>
        /// <returns>A task that completes when the signature has been written to the file.</returns>
        public async Task WriteAsync(string fileName)
        {
            using (var strm = new FileStream(fileName, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                await WriteAsync(strm);
            }
        }

        /// <summary>
        /// Writes the signature to the specified <see cref="Stream"/>.
        /// </summary>
        /// <param name="target">The <see cref="Stream"/> to write the signature to.</param>
        /// <returns>A task that completes when the signature has been written to the stream.</returns>
        public Task WriteAsync(Stream target)
        {
            var array = ToByteArray();
            return target.WriteAsync(array, 0, array.Length);
        }

        /// <summary>
        /// Returns a byte array containing the encoded signature data.
        /// </summary>
        /// <returns>A byte array containing the encoded signature data.</returns>
        public byte[] ToByteArray()
        {
            return PemFormatter.Format(
                _signedCms.Encode(),
                header: "BEGIN CMS",
                footer: "END CMS");
        }

        /// <summary>
        /// Creates a signature for the specified file, using the specified certificate chain, 
        /// and using the provided password to decrypt the certificate file
        /// </summary>
        /// <param name="targetFileName">The file to be signed</param>
        /// <param name="certificateChain">
        /// A file containing certificates to be used to sign the file (and to be embedded in the signature)
        /// </param>
        /// <param name="password">A password that can be used to decrypt the provided file</param>
        /// <returns>A task that yields the created signature data upon completion</returns>
        /// <remarks>
        /// If there are multiple certificates in the file specified by <paramref name="certificateChain"/>, 
        /// the first one will be used to encrypt the digest. If that certificate does not have the required 
        /// Extended Key Usage value (Code Signing, OID: 1.3.6.1.5.5.7.3.3), or if it does not have an 
        /// accessible private key, an exception will be thrown. All certificates in the provided file 
        /// will be embedded in the signature.
        /// </remarks>
        public static Task<Signature> SignAsync(string targetFileName, string certificateChain, string password)
        {
            var cert = new X509Certificate2(certificateChain, password);
            var chain = new X509Certificate2Collection();
            chain.Import(certificateChain, password, X509KeyStorageFlags.DefaultKeySet);
            return SignAsync(targetFileName, cert, chain);
        }

        /// <summary>
        /// Creates a signature for the specified file, using the specified certificate, 
        /// and embedding the specified additional certificates in the signature to assist 
        /// in building a certificate chain
        /// </summary>
        /// <param name="targetFileName">The file to be signed</param>
        /// <param name="signingCert">The certificate to be used to sign the file</param>
        /// <returns>A task that yields the created signature data upon completion</returns>
        /// <remarks>
        /// If the certificate specified by <paramref name="signingCert"/> does not have the required 
        /// Extended Key Usage value (Code Signing, OID: 1.3.6.1.5.5.7.3.3), or if it does not have an 
        /// accessible private key, an exception will be thrown.
        /// </remarks>
        public static Task<Signature> SignAsync(string targetFileName, X509Certificate2 signingCert)
        {
            return SignAsync(targetFileName, signingCert, new X509Certificate2Collection());
        }

        /// <summary>
        /// Creates a signature for the specified file, using the specified certificate, 
        /// and embedding the specified additional certificates in the signature to assist 
        /// in building a certificate chain
        /// </summary>
        /// <param name="targetFileName">The file to be signed</param>
        /// <param name="signingCert">The certificate to be used to sign the file</param>
        /// <param name="additionalCertificates">
        /// Additional certificates which will be embedded in the signature to assist in building
        /// a certificate chain during verification
        /// </param>
        /// <returns>A task that yields the created signature data upon completion</returns>
        /// <remarks>
        /// If the certificate specified by <paramref name="signingCert"/> does not have the required 
        /// Extended Key Usage value (Code Signing, OID: 1.3.6.1.5.5.7.3.3), or if it does not have an 
        /// accessible private key, an exception will be thrown.
        /// </remarks>
        public static async Task<Signature> SignAsync(string targetFileName, X509Certificate2 signingCert, X509Certificate2Collection additionalCertificates)
        {
            using (var strm = new FileStream(targetFileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                return await SignAsync(strm, signingCert, additionalCertificates);
            }
        }

        /// <summary>
        /// Creates a signature for the specified <see cref="Stream"/>, using the specified certificate, 
        /// and embedding the specified additional certificates in the signature to assist 
        /// in building a certificate chain
        /// </summary>
        /// <param name="targetData">The <see cref="Stream"/> containing the data to sign.</param>
        /// <param name="signingCert">The certificate to be used to sign the file.</param>
        /// <param name="additionalCertificates">
        /// Additional certificates which will be embedded in the signature to assist in building
        /// a certificate chain during verification.
        /// </param>
        /// <returns>A task that yields the created signature data upon completion</returns>
        /// <remarks>
        /// If the certificate specified by <paramref name="signingCert"/> does not have the required 
        /// Extended Key Usage value (Code Signing, OID: 1.3.6.1.5.5.7.3.3), or if it does not have an 
        /// accessible private key, an exception will be thrown.
        /// </remarks>
        public static async Task<Signature> SignAsync(Stream targetData, X509Certificate2 signingCert, X509Certificate2Collection additionalCertificates)
        {
            return Sign(await ReadStreamToMemoryAsync(targetData), signingCert, additionalCertificates);
        }

        /// <summary>
        /// Creates a signature for the specified data, using the specified certificate, 
        /// and embedding the specified additional certificates in the signature to assist
        /// in building a certificate chain
        /// </summary>
        /// <param name="targetData">The data to sign.</param>
        /// <param name="signingCert">The certificate to be used to sign the file.</param>
        /// <param name="additionalCertificates">
        /// Additional certificates which will be embedded in the signature to assist in building
        /// a certificate chain during verification.
        /// </param>
        /// <returns>The created signature data</returns>
        /// <remarks>
        /// If the certificate specified by <paramref name="signingCert"/> does not have the required 
        /// Extended Key Usage value (Code Signing, OID: 1.3.6.1.5.5.7.3.3), or if it does not have an 
        /// accessible private key, an exception will be thrown.
        /// </remarks>
        public static Signature Sign(byte[] targetData, X509Certificate2 cert, X509Certificate2Collection additionalCertificates)
        {
            // Check that the cert meets the required criteria
            var identifierType = SubjectIdentifierType.IssuerAndSerialNumber;
            if (!cert
                .Extensions
                .OfType<X509SubjectKeyIdentifierExtension>()
                .Any())
            {
                identifierType = SubjectIdentifierType.IssuerAndSerialNumber;
            }

            if (!HasEku(cert, CodeSigningEKUOid))
            {
                throw new Exception("Signing certificate must have the codeSigning extended key usage (OID: 1.3.6.1.5.5.7.3.3)");
            }

            // Create a content info and start a signed CMS
            var contentInfo = new ContentInfo(targetData);
            var signedCms = new SignedCms(contentInfo, detached: true);

            // Create a signer info for the signature
            var signer = new CmsSigner(identifierType, cert);
            signer.DigestAlgorithm = Oid.FromOidValue(Sha256Oid, OidGroup.HashAlgorithm);

            // We do want the whole chain in the file, but we can't control how
            // CmsSigner builds the chain and add our additional certificates.
            // So, we tell it not to worry and we manually build the chain and
            // add it to the signer.
            signer.IncludeOption = X509IncludeOption.EndCertOnly;

            // Embed all the certificates in the CMS
            var chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.AddRange(additionalCertificates);
            chain.Build(cert);
            foreach (var element in chain.ChainElements)
            {
                // Don't re-embed the signing certificate!
                if (!Equals(element.Certificate, cert))
                {
                    signer.Certificates.Add(element.Certificate);
                }
            }

            // Compute the signature!
            signedCms.ComputeSignature(signer, silent: true);

            // Load the signature in to the object
            return new Signature(signedCms);
        }

        /// <summary>
        /// Loads and verifies the digest of the signature in the signature file specified by
        /// <paramref name="signatureFile"/> against the content in the file specified by 
        /// <paramref name="fileName"/>.
        /// </summary>
        /// <param name="fileName">The file containing the content to be verified.</param>
        /// <param name="signatureFile">The file containing the signature to verify.</param>
        /// <returns>A task that yields the loaded signature data upon completion</returns>
        /// <remarks>
        /// This method does NOT check if the certificate that generated the signature is trusted,
        /// only that the signer's public key can be used to decrypt the digest and that the
        /// digest matches the content provided in <paramref name="fileName"/>. Trust verification
        /// is provided by the <see cref="TrustContext"/> class.
        /// </remarks>
        public static async Task<Signature> VerifyAsync(string fileName, string signatureFile)
        {
            using (var fileStream = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                using (var signatureStream = new FileStream(signatureFile, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    return await VerifyAsync(fileStream, signatureStream);
                }
            }
        }

        /// <summary>
        /// Loads and verifies the digest of the signature in the signature data provided in
        /// <paramref name="signature"/> against the content in the data provided in
        /// <paramref name="content"/>.
        /// </summary>
        /// <param name="content">A <see cref="Stream"/> that can be used to read the content to be verified.</param>
        /// <param name="signature">A <see cref="Stream"/> that can be used to read the signature to verify.</param>
        /// <returns>A task that yields the loaded signature data upon completion</returns>
        /// <remarks>
        /// This method does NOT check if the certificate that generated the signature is trusted,
        /// only that the signer's public key can be used to decrypt the digest and that the
        /// digest matches the content provided in <paramref name="content"/>. Trust verification
        /// is provided by the <see cref="TrustContext"/> class.
        /// </remarks>
        public static async Task<Signature> VerifyAsync(Stream content, Stream signature)
        {
            return Verify(await ReadStreamToMemoryAsync(content), await ReadStreamToMemoryAsync(signature));
        }

        /// <summary>
        /// Loads and verifies the digest of the signature in the signature data provided in
        /// <paramref name="signature"/> against the content in the data provided in
        /// <paramref name="content"/>.
        /// </summary>
        /// <param name="content">The content to be verified.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns>A task that yields the loaded signature data upon completion</returns>
        /// <remarks>
        /// This method does NOT check if the certificate that generated the signature is trusted,
        /// only that the signer's public key can be used to decrypt the digest and that the
        /// digest matches the content provided in <paramref name="content"/>. Trust verification
        /// is provided by the <see cref="TrustContext"/> class.
        /// </remarks>
        public static Signature Verify(byte[] content, byte[] signature)
        {
            // The file is actually UTF-8 Base-64 Encoded, so decode that
            var decoded = PemFormatter.Unformat(signature);

            // Load the content
            var contentInfo = new ContentInfo(content);

            // Create a signed cms and decode the signature into it
            var signedCms = new SignedCms(contentInfo, detached: true);
            signedCms.Decode(decoded);

            signedCms.CheckSignature(verifySignatureOnly: true);

            // Build the signature object
            return new Signature(signedCms);
        }

        private static async Task<byte[]> ReadStreamToMemoryAsync(Stream file)
        {
            byte[] content;
            using (var strm = new MemoryStream())
            {
                await file.CopyToAsync(strm);
                await strm.FlushAsync();
                content = strm.ToArray();
            }

            return content;
        }

        private static bool HasEku(X509Certificate2 cert, string oid)
        {
            return cert
                .Extensions
                .OfType<X509EnhancedKeyUsageExtension>()
                .Any(e => e.EnhancedKeyUsages.Cast<Oid>().Any(o => Equals(o.Value, oid)));
        }
    }
}