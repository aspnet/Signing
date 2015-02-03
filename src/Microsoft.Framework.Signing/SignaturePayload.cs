using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace Microsoft.Framework.Signing
{
    /// <summary>
    /// Represents the payload of a signature file
    /// </summary>
    /// <remarks>
    /// The signature payload is the ASN.1 type <c>SignaturePayload</c> as defined below:
    /// <code>
    /// SignaturePayload ::= SEQUENCE {
    ///     version             INTEGER { v1(1) },
    ///     contentIdentifier   UTF8String,
    ///     contentDigest       DigestValue }
    /// DigestValue ::= SEQUENCE  {
    ///     digestAlgorithm     OBJECT IDENTIFIER
    ///     digest              OCTET STRING }
    /// </code>
    /// </remarks>
    public class SignaturePayload
    {
        public static readonly int CurrentVersion = 1;
        public static readonly int MaxSupportedVersion = CurrentVersion;

        public int Version { get; }
        public string ContentIdentifier { get; }
        public Oid DigestAlgorithm { get; }
        public byte[] Digest { get; }

        public SignaturePayload(string contentIdentifier, Oid digestAlgorithm, byte[] digest)
            : this(CurrentVersion, contentIdentifier, digestAlgorithm, digest)
        {
        }

        internal SignaturePayload(int version, string contentIdentifier, Oid digestAlgorithm, byte[] digest)
        {
            Version = version;
            ContentIdentifier = contentIdentifier;
            DigestAlgorithm = digestAlgorithm;
            Digest = digest;
        }

        public bool Verify(string payloadFile)
        {
            using (var stream = new FileStream(payloadFile, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                return Verify(stream);
            }
        }

        public bool Verify(Stream stream)
        {
            var algorithm = HashAlgorithm.Create(DigestAlgorithm.FriendlyName);
            var actualDigest = algorithm.ComputeHash(stream);

            return Enumerable.SequenceEqual(Digest, actualDigest);
        }

        public byte[] Encode()
        {
            // Manually encode using ASN.1 Distinguished Encoding Rules
            return Asn1Utils.EncodePayload(this);
        }

        public static SignaturePayload Compute(string fileName, string digestAlgorithm)
        {
            using (var stream = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                return Compute(Path.GetFileName(fileName), stream, digestAlgorithm);
            }
        }

        public static SignaturePayload Compute(string contentIdentifier, byte[] input, string digestAlgorithm)
        {
            using (var stream = new MemoryStream(input))
            {
                return Compute(contentIdentifier, stream, digestAlgorithm);
            }
        }

        public static SignaturePayload Compute(string contentIdentifier, Stream input, string digestAlgorithm)
        {
            var algorithm = HashAlgorithm.Create(digestAlgorithm);
            var oid = CryptoConfig.MapNameToOID(digestAlgorithm);

            var digest = algorithm.ComputeHash(input);
            return new SignaturePayload(contentIdentifier, new Oid(oid), digest);
        }

        public static SignaturePayload Decode(byte[] content)
        {
            var result = Asn1Utils.TryDecodePayload(content);
            if (result == null)
            {
                throw new FormatException("Invalid Signature Payload value!");
            }
            return result;
        }
    }
}