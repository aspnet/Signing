using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.Framework.Signing
{
    internal class Asn1Utils
    {
        // ASN.1 Structure
        // SignaturePayload ::= SEQUENCE {
        //     version             INTEGER { v1(1) },
        //     contentIdentifier   UTF8String,
        //     contentDigest       DigestValue }
        // DigestValue ::= SEQUENCE  {
        //     digestAlgorithm     OBJECT IDENTIFIER
        //     digest              OCTET STRING }

        internal static byte[] EncodePayload(SignaturePayload signaturePayload)
        {
            using (var stream = new MemoryStream())
            {
                using (var writer = new BinaryWriter(stream))
                {
                    // Generate the sub-elements
                    byte[] contents = EncodePayloadContents(signaturePayload);

                    // Write the tag and length
                    writer.Write((byte)0x30); // Tag = SEQUENCE (constructed)
                    WriteLength(writer, contents.Length); // Length
                    writer.Write(contents); // Value
                }
                return stream.ToArray();
            }
        }

        internal static SignaturePayload TryDecodePayload(byte[] content)
        {
            // We only accept DER-formatted payloads and we expect everything to be perfect,
            // or we just abort.

            using (var stream = new MemoryStream(content))
            using (var reader = new BinaryReader(stream))
            {
                var contents = ReadSequenceContents(reader);
                if (contents == null)
                {
                    return null;
                }
                return TryDecodePayloadContents(contents);
            }
        }

        private static byte[] ReadSequenceContents(BinaryReader reader) {
            if (reader.ReadByte() != 0x30)
            {
                return null; // Invalid Tag!
            }
            var len = ReadLength(reader);

            // Read the content
            var contents = reader.ReadBytes(len);
            return contents;
        }

        private static SignaturePayload TryDecodePayloadContents(byte[] content)
        {
            using (var stream = new MemoryStream(content))
            using (var reader = new BinaryReader(stream))
            {
                var version = ReadVersion(reader);
                if (version == null)
                {
                    return null;
                }
                var identifier = ReadUtf8String(reader);
                if (identifier == null)
                {
                    return null;
                }
                var digest = ReadSequenceContents(reader);

                return TryDecodeDigestValue(version.Value, identifier, digest);
            }
        }

        private static SignaturePayload TryDecodeDigestValue(int version, string identifier, byte[] content)
        {
            using (var stream = new MemoryStream(content))
            using (var reader = new BinaryReader(stream))
            {
                var digestAlgorithm = ReadOid(reader);
                if (digestAlgorithm == null)
                {
                    return null;
                }
                var digest = ReadOctetString(reader);
                if (digest == null)
                {
                    return null;
                }
                return new SignaturePayload(
                    version,
                    identifier,
                    digestAlgorithm,
                    digest);
            }
        }

        private static Oid ReadOid(BinaryReader reader)
        {
            if (reader.ReadByte() != 0x06)
            {
                return null; // Not an OID!
            }
            var len = ReadLength(reader);
            var octets = reader.ReadBytes(len);

            Debug.Assert(len >= 2);

            var segments = new List<int>();
            segments.Add(octets[0] / 40); // First segment
            segments.Add(octets[0] % 40); // Second segment

            // Remaining octets are encoded as base-128 digits, where the highest bit indicates if more digits exist
            int idx = 1;
            while (idx < octets.Length)
            {
                int val = 0;
                do
                {
                    val = (val * 128) + (octets[idx] & 0x7F); // Take low 7 bits of octet
                    idx++;
                } while ((octets[idx - 1] & 0x80) != 0); // Loop while high bit is 1
                segments.Add(val);
            }

            return new Oid(string.Join(".", segments.Select(s => s.ToString())));
        }

        private static byte[] ReadOctetString(BinaryReader reader)
        {
            if (reader.ReadByte() != 0x04)
            {
                return null; // Not an octet string!
            }
            var len = ReadLength(reader);
            return reader.ReadBytes(len);
        }

        private static string ReadUtf8String(BinaryReader reader)
        {
            if (reader.ReadByte() != 0x0C)
            {
                return null; // It's not a UTF8String!
            }
            var len = ReadLength(reader);
            var content = reader.ReadBytes(len);
            return Encoding.UTF8.GetString(content);
        }

        private static int? ReadVersion(BinaryReader reader)
        {
            if (reader.ReadByte() != 0x02)
            {
                return null; // It's not an INTEGER!
            }
            if (reader.ReadByte() != 0x01)
            {
                return null; // It's too long!
            }
            return reader.ReadByte(); // It's juuuuust right.
        }

        private static int ReadLength(BinaryReader reader)
        {
            byte lowLen = reader.ReadByte();
            var len = lowLen & 0x7F;
            if ((lowLen & 0x80) != 0 && len != 0) // Bit 8 set and not indeterminate length?
            {
                // Len is actually the number of length octets left, each one is a base 256 "digit"
                var lengthBytes = reader.ReadBytes(len);
                len = lengthBytes.Aggregate(
                    seed: 0,
                    func: (l, r) => (l * 256) + r);
            }
            return len;
        }

        private static byte[] EncodePayloadContents(SignaturePayload signaturePayload)
        {
            using (var stream = new MemoryStream())
            {
                using (var writer = new BinaryWriter(stream))
                {
                    // Write the version
                    writer.Write((byte)0x02); // Tag = INTEGER
                    writer.Write((byte)0x01); // Length
                    writer.Write((byte)signaturePayload.Version); // Value

                    // Write the content identifier
                    var strBytes = Encoding.UTF8.GetBytes(signaturePayload.ContentIdentifier);
                    writer.Write((byte)0x0C); // Tag = UTF8String
                    WriteLength(writer, strBytes.Length); // Length
                    writer.Write(strBytes);

                    // Write the digest value
                    byte[] digestValue = EncodeDigestValue(signaturePayload);

                    writer.Write((byte)0x30); // Tag = SEQUENCE
                    WriteLength(writer, digestValue.Length); // Length
                    writer.Write(digestValue); // Value
                }
                return stream.ToArray();
            }
        }

        private static byte[] EncodeDigestValue(SignaturePayload signaturePayload)
        {
            using (var stream = new MemoryStream())
            {
                using (var writer = new BinaryWriter(stream))
                {
                    WriteOid(writer, signaturePayload.DigestAlgorithm);

                    writer.Write((byte)0x04); // Tag = OCTET STRING
                    WriteLength(writer, signaturePayload.Digest.Length);
                    writer.Write(signaturePayload.Digest);
                }

                return stream.ToArray();
            }
        }

        private static void WriteOid(BinaryWriter writer, Oid digestAlgorithm)
        {
            // Parse the segments
            // (We are extremely confident that the segments are valid numbers)
            var segments = digestAlgorithm.Value
                .Split('.')
                .Select(s => int.Parse(s))
                .ToList();

            // Again, we are confident the segments list will have at least 2 items.
            Debug.Assert(segments.Count >= 2);

            // Determine the first byte of the value
            byte firstOctet = (byte)((40 * segments[0]) + segments[1]);

            // Calculate the remaining bytes
            var oidBytes = segments.Skip(2).SelectMany(segment =>
            {
                var digits = GenerateBaseNDigits(segment, @base: 128);
                for (int i = 0; i < digits.Count - 1; i++)
                {
                    digits[i] = (byte)(digits[i] | 0x80); // Set first bit to 1 to indicate more digits are coming
                }
                return digits;
            }).ToArray();

            // Write all the things!
            writer.Write((byte)0x06); // Tag = OBJECT IDENTIFIER
            WriteLength(writer, oidBytes.Length + 1);
            writer.Write(firstOctet);
            writer.Write(oidBytes);
        }

        private static void WriteLength(BinaryWriter writer, int length)
        {
            if (length <= 127)
            {
                writer.Write((byte)(length & 0x7F));
            }
            else
            {
                var digits = GenerateBaseNDigits(length, @base: 256);

                // Write the number of length digits
                writer.Write((byte)(digits.Count | 0x80));

                // Write the length digits
                writer.Write(digits.ToArray());
            }
        }

        private static List<byte> GenerateBaseNDigits(long value, int @base)
        {
            List<byte> digits = new List<byte>();
            while ((value > (@base - 1)) || (value < -(@base - 1)))
            {
                var digit = (int)(value % @base);
                value = value / @base;

                // Insert at the front so we "unreverse" the digits as we calculate them
                digits.Insert(0, (byte)digit);
            }
            digits.Insert(0, (byte)value);

            return digits;
        }
    }
}