using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Framework.Asn1;

namespace Microsoft.Framework.Signing
{
    public class Signature
    {
        public static readonly string DefaultDigestAlgorithmName = "sha256";
        public static readonly int CurrentVersion = 1;

        internal static readonly int MaxSupportedVersion = CurrentVersion;

        private static readonly string SignatureRequestPemHeader = "BEGIN SIGNATURE REQUEST";
        private static readonly string SignatureRequestPemFooter = "END SIGNATURE REQUEST";
        private static readonly string SignaturePemHeader = "BEGIN SIGNATURE";
        private static readonly string SignaturePemFooter = "END SIGNATURE";

        private SignedCms _signature = null;
        private SignaturePayload _payload;

        public int Version { get { return _payload.Version; } }
        public IReadOnlyList<SignatureEntry> Entries { get { return _payload.Entries; } }
        public bool IsSigned { get { return _signature != null; } }

        public Signer Signer { get; }
        public X509Certificate2Collection Certificates { get { return _signature?.Certificates; } }


        /// <summary>
        /// Constructs a new signature request for the specified file
        /// </summary>
        /// <param name="signatureEntry">A signature entry describing the file to create a signature request for</param>
        /// <remarks>
        /// Until <see cref="Sign"/> is called, this structure represents a signature request.
        /// </remarks>
        public Signature(SignatureEntry signatureEntry)
            : this(new SignaturePayload(CurrentVersion, signatureEntry)) { }

        private Signature(SignaturePayload payload)
        {
            _payload = payload;
        }

        private Signature(SignedCms cms)
        {
            _payload = SignaturePayload.Decode(cms.ContentInfo.Content);
            _signature = cms;

            Signer = Signer.FromSignerInfo(_signature.SignerInfos.Cast<SignerInfo>().FirstOrDefault());
        }

        /// <summary>
        /// Encodes the signature/signature request for storage
        /// </summary>
        /// <returns></returns>
        public byte[] Encode()
        {
            if (!IsSigned)
            {
                return new PemData(
                    header: SignatureRequestPemHeader,
                    data: _payload.Encode(),
                    footer: SignatureRequestPemFooter).Encode();
            }
            else
            {
                return new PemData(
                    header: SignaturePemHeader,
                    data: _signature.Encode(),
                    footer: SignaturePemFooter).Encode();
            }
        }


        /// <summary>
        /// Writes the signature/signature request to the specified stream
        /// </summary>
        /// <param name="destination">The stream to write the signature data to.</param>
        public Task WriteAsync(Stream destination)
        {
            var encoded = Encode();
            return destination.WriteAsync(encoded, 0, encoded.Length);
        }

        /// <summary>
        /// Writes the signature/signature request to the specified file
        /// </summary>
        /// <param name="fileName">The file to write the signature data to.</param>
        public async Task WriteAsync(string fileName)
        {
            using (var stream = new FileStream(fileName, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                await WriteAsync(stream);
            }
        }

        /// <summary>
        /// Attempts to decode the specified file as a Signature or Signature Request.
        /// Returns null if it fails to decode
        /// </summary>
        /// <param name="fileName">The file to decode</param>
        /// <returns></returns>
        public static async Task<Signature> TryDecodeAsync(string fileName)
        {
            using (var stream = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                return await TryDecodeAsync(stream);
            }
        }

        /// <summary>
        /// Attempts to decode the specified data as a Signature or Signature Request.
        /// Returns null if it fails to decode
        /// </summary>
        /// <param name="stream">The data to decode</param>
        /// <returns></returns>
        public static async Task<Signature> TryDecodeAsync(Stream stream)
        {
            PemData pem = await PemData.TryDecodeAsync(stream);
            if (pem == null)
            {
                // Not valid PEM!
                return null;
            }

            // Figure out what format the input is in
            if (string.Equals(pem.Header, SignatureRequestPemHeader, StringComparison.OrdinalIgnoreCase))
            {
                return DecodeRequest(pem.Data);
            }
            else if (string.Equals(pem.Header, SignaturePemHeader, StringComparison.OrdinalIgnoreCase))
            {
                return DecodeSignature(pem.Data);
            }
            else
            {
                // Unknown input
                return null;
            }
        }

        /// <summary>
        /// Signs the signature request with the specified certificate. Uses only the Operating
        /// System certificate store (if present) to build the full chain for the signing cert.
        /// </summary>
        /// <param name="signingCert">The certificate and private key to sign the document with</param>
        public void Sign(X509Certificate2 signingCert)
        {
            Sign(signingCert, null);
        }
        
        /// <summary>
        /// Signs the signature request with the specified certificate,
        /// and uses the provided additional certificates (along with the Operating System certificate
        /// store, if present) to build the full chain for the signing cert and embed that in the
        /// signature.
        /// </summary>
        /// <param name="signingCert">The certificate and private key to sign the document with</param>
        /// <param name="additionalCertificates">Additional certificates to use when building the chain to embed</param>
        public void Sign(X509Certificate2 signingCert, X509Certificate2Collection additionalCertificates)
        {
            if (_signature != null) {
                throw new InvalidOperationException("A signature already exists");
            }

            // Create the content info
            var content = new ContentInfo(_payload.Encode());

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
            if (additionalCertificates != null)
            {
                chain.ChainPolicy.ExtraStore.AddRange(additionalCertificates);
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

            // Create the message and sign it
            // Use a local variable so that if the signature fails to compute, this object
            // remains in a "good" state.
            var cms = new SignedCms(content);
            cms.ComputeSignature(signer);
            _signature = cms;
        }

        private static Signature DecodeRequest(byte[] data)
        {
            var payload = SignaturePayload.Decode(data);
            return new Signature(payload);
        }

        private static Signature DecodeSignature(byte[] data)
        {
            SignedCms cms = new SignedCms();
            cms.Decode(data);
            return new Signature(cms);
        }

        // Support class used to represent the payload of the signature itself.
        private class SignaturePayload
        {
            public int Version { get; }
            public IReadOnlyList<SignatureEntry> Entries { get; }

            public SignaturePayload(int version, SignatureEntry entry)
            {
                Version = version;
                Entries = new List<SignatureEntry>() { entry }.AsReadOnly();
            }

            public byte[] Encode()
            {
                // Write the signature payload
                var payload = new Asn1Sequence(
                    new Asn1Integer(Signature.CurrentVersion),
                    new Asn1Set(Entries.Select(e => e.ToAsn1())));
                return DerEncoder.Encode(payload);
            }

            public static SignaturePayload Decode(byte[] data) {
                var parsed = BerParser.Parse(data);
                var root = parsed as Asn1Sequence;
                if (root == null || root.Values.Count < 2)
                {
                    // Invalid Request format
                    return null;
                }
                var ver = root.Values[0] as Asn1Integer;
                var signatures = root.Values[1] as Asn1Set;
                if (ver == null || signatures == null)
                {
                    // Invalid Request format
                    return null;
                }

                if (ver.Value > MaxSupportedVersion || signatures.Values.Count != 1)
                {
                    // Version not supported!
                    return null;
                }

                var entry = SignatureEntry.TryFromAsn1(signatures.Values.Single());
                if (entry == null)
                {
                    return null;
                }

                return new SignaturePayload((int)ver.Value, entry);
            }
        }
    }
}