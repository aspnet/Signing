using System;
using System.Linq;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Text;
using System.Security.Cryptography.Pkcs;

namespace PackageSigning
{
    public class Signature
    {
        public static readonly string DefaultHashAlgorithmName = "sha256";
        public static readonly HashAlgorithm DefaultHashAlgorithm = (HashAlgorithm)CryptoConfig.CreateFromName(DefaultHashAlgorithmName);
        private static readonly string Sha256Oid = "2.16.840.1.101.3.4.2.1";
        private static readonly string CodeSigningEKUOid = "1.3.6.1.5.5.7.3.3";

        private SignedCms _signedCms;

        public Signer Signer { get; private set; }
        public DateTime? ValidFromUtc { get; private set; }
        public DateTime? ValidToUtc { get; private set; }
        public DateTime TimestampUtc { get; private set; }

        public bool WithinValidityPeriod {
            get
            {
                return (ValidFromUtc == null || ValidFromUtc.Value <= TimestampUtc) &&
                    (ValidToUtc == null || ValidToUtc.Value >= TimestampUtc);
            }
        }

        private Signature(SignedCms signedCms)
        {
            _signedCms = signedCms;

            // Read the signer
            var signerInfo = _signedCms.SignerInfos.Cast<SignerInfo>().FirstOrDefault();
            Signer = Signer.FromSignerInfo(signerInfo, _signedCms.Certificates);

            ValidFromUtc = Signer.SignerCertificate.NotBefore;
            ValidToUtc = Signer.SignerCertificate.NotAfter;
            TimestampUtc = DateTime.UtcNow;
        }

        public async Task WriteAsync(string fileName)
        {
            using (var strm = new FileStream(fileName, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                await WriteAsync(strm);
            }
        }

        public Task WriteAsync(Stream target)
        {
            var array = ToByteArray();
            return target.WriteAsync(array, 0, array.Length);
        }

        public byte[] ToByteArray()
        {
            return PemFormatter.Format(
                _signedCms.Encode(),
                header: "BEGIN CMS",
                footer: "END CMS");
        }

        public static Task<Signature> SignAsync(string targetFileName, string certificateChain, string password)
        {
            var cert = new X509Certificate2(certificateChain, password);
            var chain = new X509Certificate2Collection();
            chain.Import(certificateChain, password, X509KeyStorageFlags.DefaultKeySet);
            return SignAsync(targetFileName, cert, chain);
        }

        public static async Task<Signature> SignAsync(string targetFileName, X509Certificate2 cert, X509Certificate2Collection additionalCertificates)
        {
            using (var strm = new FileStream(targetFileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                return await SignAsync(strm, cert, additionalCertificates);
            }
        }

        public static async Task<Signature> SignAsync(Stream targetData, X509Certificate2 cert, X509Certificate2Collection additionalCertificates)
        {
            return Sign(await ReadStreamToMemoryAsync(targetData), cert, additionalCertificates);
        }

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

        public static async Task<Signature> VerifyAsync(Stream file, Stream signature)
        {
            return Verify(await ReadStreamToMemoryAsync(file), await ReadStreamToMemoryAsync(signature));
        }

        public static Signature Verify(byte[] file, byte[] signature)
        {
            // The file is actually UTF-8 Base-64 Encoded, so decode that
            var decoded = PemFormatter.Unformat(signature);

            // Load the content
            var contentInfo = new ContentInfo(file);

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