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
using Microsoft.Framework.Signing.Native;

namespace Microsoft.Framework.Signing
{
    public class Signature
    {
        public static readonly string DefaultDigestAlgorithmName = "sha256";

        private static readonly string SignatureRequestPemHeader = "BEGIN SIGNATURE REQUEST";
        private static readonly string SignatureRequestPemFooter = "END SIGNATURE REQUEST";
        private static readonly string SignaturePemHeader = "BEGIN SIGNATURE";
        private static readonly string SignaturePemFooter = "END SIGNATURE";

        private SignedCms _signature = null;

        public bool IsSigned { get { return _signature != null; } }
        public bool IsTimestamped { get { return false; } }

        public SignaturePayload Payload { get; private set; }
        public Signer Signer { get; private set; }
        public X509Certificate2Collection Certificates { get { return _signature?.Certificates; } }

        /// <summary>
        /// Constructs a new signature request for the specified file
        /// </summary>
        /// <param name="payload">A signature entry describing the file to create a signature request for</param>
        /// <remarks>
        /// Until <see cref="Sign"/> is called, this structure represents a signature request.
        /// </remarks>
        public Signature(SignaturePayload payload)
        {
            Payload = payload;
        }

        private Signature(SignedCms cms)
        {
            SetSignature(cms);
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
                    data: Payload.Encode(),
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

        public void Timestamp(Uri timestampingAuthority)
        {
            Timestamp(timestampingAuthority, DefaultDigestAlgorithmName);
        }

        public void Timestamp(Uri timestampingAuthority, string requestedDigestAlgorithmName)
        {
            var digestAlgorithmOid = CryptoConfig.MapNameToOID(requestedDigestAlgorithmName);
            if (digestAlgorithmOid == null)
            {
                throw new InvalidOperationException("Unknown digest algorithm: " + requestedDigestAlgorithmName);
            }

            // Get the encrypted digest to timestamp
            byte[] digest;
            using (var cms = NativeCms.Decode(_signature.Encode(), detached: false))
            {
                digest = cms.GetEncryptedDigest();
            }

            // Request a timestamp and add it to the signature as an unsigned attribute
            var timestamp = RFC3161.RequestTimestamp(digest, digestAlgorithmOid, timestampingAuthority);

            //// Build the certificate chain locally to ensure we store the whole thing
            //var chain = new X509Chain();
            //if (!chain.Build(timestamp.SignerInfos[0].Certificate))
            //{
            //    throw new InvalidOperationException("Unable to build certificate chain for timestamp!");
            //}

            //// Reopen the timestamp as a native cms so we can modify it
            //byte[] rawTimestamp;
            //using (var cms = NativeCms.Decode(timestamp.Encode(), detached: false))
            //{
            //    cms.AddCertificates(chain.ChainElements
            //        .Cast<X509ChainElement>()
            //        .Where(c => !timestamp.Certificates.Contains(c.Certificate))
            //        .Select(c => c.Certificate.Export(X509ContentType.Cert)));
            //    rawTimestamp = cms.Encode();
            //}

            // Reopen the signature as a native cms so we can modify it
            SignedCms newSignature = new SignedCms();
            using (var cms = NativeCms.Decode(_signature.Encode(), detached: false))
            {
                cms.AddTimestamp(timestamp.Encode());
                newSignature.Decode(cms.Encode());
            }

            // Reset the signature
            SetSignature(newSignature);
        }

        /// <summary>
        /// Signs the signature request with the specified certificate. Uses only the Operating
        /// System certificate store (if present) to build the full chain for the signing cert.
        /// </summary>
        /// <param name="signingCert">The certificate and private key to sign the document with</param>
        public void Sign(X509Certificate2 signingCert)
        {
            Sign(signingCert, null, null);
        }

        /// <summary>
        /// Signs the signature request with the specified certificate,
        /// and uses the provided additional certificates (along with the Operating System certificate
        /// store, if present) to build the full chain for the signing cert and embed that in the
        /// signature.
        /// </summary>
        /// <param name="signingCert">The certificate and private key to sign the document with</param>
        /// <param name="chainBuildingCertificates">Additional certificates to use when building the chain to embed</param>
        public void Sign(X509Certificate2 signingCert, X509Certificate2Collection chainBuildingCertificates)
        {
            Sign(signingCert, chainBuildingCertificates, null);
        }

        /// <summary>
        /// Signs the signature request with the specified certificate, embeds all the specified additional certificates
        /// in the signature, and uses the provided additional certificates (along with the Operating
        /// System certificate store, if present) to build the full chain for the signing cert and
        /// embed that in the signature.
        /// </summary>
        /// <param name="signingCert">The certificate and private key to sign the document with</param>
        /// <param name="chainBuildingCertificates">Additional certificates to use when building the chain to embed</param>
        /// <param name="certificatesToEmbed">Additional certificates to add to the signature</param>
        public void Sign(X509Certificate2 signingCert, X509Certificate2Collection chainBuildingCertificates, X509Certificate2Collection certificatesToEmbed)
        {
            if (_signature != null)
            {
                throw new InvalidOperationException("A signature already exists");
            }

            // Create the content info
            var content = new ContentInfo(Payload.Encode());

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
            _signature = cms;
        }

        private void SetSignature(SignedCms cms)
        {
            Payload = SignaturePayload.Decode(cms.ContentInfo.Content);
            _signature = cms;

            Signer = Signer.FromSignerInfo(_signature.SignerInfos.Cast<SignerInfo>().FirstOrDefault());
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
    }
}