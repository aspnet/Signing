using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Framework.Asn1;

namespace Microsoft.Framework.Signing
{
    public class SignatureEntry
    {
        public int Version { get; }
        public string ContentIdentifier { get; }
        public string DigestAlgorithm { get; }
        public byte[] Digest { get; }

        public SignatureEntry(string contentIdentifier, string digestAlgorithm, byte[] digest)
            : this(Signature.CurrentVersion, contentIdentifier, digestAlgorithm, digest)
        {
        }

        private SignatureEntry(int version, string contentIdentifier, string digestAlgorithm, byte[] digest)
        {
            Version = version;
            ContentIdentifier = contentIdentifier;
            DigestAlgorithm = digestAlgorithm;
            Digest = digest;
        }

        public static SignatureEntry Compute(string fileName, string digestAlgorithm)
        {
            using (var stream = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                return Compute(Path.GetFileName(fileName), stream, digestAlgorithm);
            }
        }

        public static SignatureEntry Compute(string contentIdentifier, byte[] input, string digestAlgorithm)
        {
            using (var stream = new MemoryStream(input))
            {
                return Compute(contentIdentifier, stream, digestAlgorithm);
            }
        }

        public static SignatureEntry Compute(string contentIdentifier, Stream input, string digestAlgorithm)
        {
            var algorithm = HashAlgorithm.Create(digestAlgorithm);
            var oid = CryptoConfig.MapNameToOID(digestAlgorithm);

            var digest = algorithm.ComputeHash(input);
            return new SignatureEntry(contentIdentifier, oid, digest);
        }

        internal Asn1Value ToAsn1()
        {
            return new Asn1Sequence(
                new Asn1Integer(Signature.CurrentVersion),
                new Asn1String(ContentIdentifier, Asn1StringType.UTF8String),
                Asn1Oid.Parse(DigestAlgorithm),
                new Asn1OctetString(Digest));
        }

        internal static SignatureEntry TryFromAsn1(Asn1Value val)
        {
            var entry = val as Asn1Sequence;
            if (entry == null || entry.Values.Count < 4)
            {
                // Invalid Request format
                return null;
            }
            var entryVer = entry.Values[0] as Asn1Integer;
            var entryId = entry.Values[1] as Asn1String;
            var entryAlg = entry.Values[2] as Asn1Oid;
            var entryDig = entry.Values[3] as Asn1OctetString;
            if (entryVer == null || 
                entryId == null || 
                entryAlg == null || 
                entryDig == null || 
                entryVer.Value > Signature.MaxSupportedVersion)
            {
                // Invalid Request format
                return null;
            }

            return new SignatureEntry(
                (int)entryVer.Value,
                entryId.Value,
                entryAlg.Oid,
                entryDig.Value);
        }
    }
}