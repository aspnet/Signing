using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Framework.Signing.Native;

namespace Microsoft.Framework.Signing
{
    public class Signature
    {
        public static readonly string DefaultDigestAlgorithmName = "sha256";

        private static readonly string SignatureRequestPemHeader = "BEGIN FILE SIGNING REQUEST";
        private static readonly string SignatureRequestPemFooter = "END FILE SIGNING REQUEST";
        private static readonly string SignaturePemHeader = "BEGIN FILE SIGNATURE";
        private static readonly string SignaturePemFooter = "END FILE SIGNATURE";

        private byte[] _encryptedDigest = null;
        private SignedCms _signature = null;
        private TimeStampToken _timestamp = null;

        public bool IsSigned { get { return _signature != null; } }
        public bool IsTimestamped { get { return _timestamp != null; } }

        public SignaturePayload Payload { get; private set; }
        public Signatory Signatory { get; private set; }
        public TimeStampToken Timestamp { get { return _timestamp; } }
        public X509Certificate2Collection Certificates { get { return _signature?.Certificates; } }

        public DateTime? TrustedSigningTimeUtc { get; private set; }

        protected internal byte[] EncryptedDigest { get { return _encryptedDigest; } }

        internal Signature(SignaturePayload payload)
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

        protected internal virtual void SetSignature(SignedCms cms)
        {
            TrustedSigningTimeUtc = null;
            Payload = SignaturePayload.Decode(cms.ContentInfo.Content);
            _signature = cms;

            // Load the encrypted digest using the native APIs
            using (var nativeCms = NativeCms.Decode(cms.Encode(), detached: false))
            {
                _encryptedDigest = nativeCms.GetEncryptedDigest();
            }

            var signerInfo = cms.SignerInfos.Cast<SignerInfo>().FirstOrDefault();
            if (signerInfo != null)
            {
                Signatory = Signatory.FromSignerInfo(signerInfo);
            }
        }

        protected internal virtual void SetTimestamp(TimeStampToken token)
        {
            _timestamp = token;

            if (_timestamp.IsTrusted)
            {
                TrustedSigningTimeUtc = _timestamp.TimestampUtc;
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