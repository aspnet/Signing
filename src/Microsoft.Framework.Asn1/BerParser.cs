using System;
using System.Linq;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Microsoft.Framework.Asn1
{
    public class BerParser
    {

        public virtual Asn1Value Parse(Stream input)
        {
            using (var reader = new BinaryReader(input))
            {
                return ReadValue(reader);
            }
        }

        private Asn1Value ReadValue(BinaryReader reader)
        {
            // Read the tag
            var header = ReadHeader(reader);

            if (header.Class == Asn1Class.ContextSpecific)
            {
                var inner = ReadValue(reader);
                return new Asn1Tagged(
                    header.Class,
                    header.Tag,
                    header.Length,
                    header.Encoding,
                    inner);
            }

            switch (header.Tag)
            {
                case 0x10:
                    return ParseSequence(header, reader);
                case 0x06:
                    return ParseOid(header, reader);
                default:
                    return ParseUnknown(header, reader);
            }
        }

        private Asn1Oid ParseOid(BerHeader header, BinaryReader reader)
        {
            byte[] octets = reader.ReadBytes(header.Length);

            // First Octet = 40*v1+v2
            int first = octets[0] / 40;
            int second = octets[0] % 40;

            // Remaining octets use some weird encoding
            List<int> segments = new List<int>();
            segments.Add(first);
            segments.Add(second);

            int idx = 1;
            while (idx < octets.Length)
            {
                int val = 0;
                do
                {
                    val = (val * 128) + (octets[idx] & 0x7F); // Take low 7 bits of octet
                    idx++;
                } while ((octets[idx-1] & 0x80) != 0); // Loop while high bit is 1
                segments.Add(val);
            }

            return new Asn1Oid(
                header.Class,
                header.Tag,
                header.Length,
                header.Encoding,
                String.Join(".", segments.Select(i => i.ToString())));
        }

        private Asn1Sequence ParseSequence(BerHeader header, BinaryReader reader)
        {
            long start = reader.BaseStream.Position;
            List<Asn1Value> values = new List<Asn1Value>();
            while ((reader.BaseStream.Position - start) < header.Length)
            {
                values.Add(ReadValue(reader));
            }
            return new Asn1Sequence(
                header.Class,
                header.Tag,
                header.Length,
                header.Encoding,
                values);
        }

        private Asn1Value ParseUnknown(BerHeader header, BinaryReader reader)
        {
            // Read the contents
            var content = reader.ReadBytes(header.Length);

            // Construct the value!
            return new Asn1Unknown(
                header.Class,
                header.Tag,
                header.Length,
                header.Encoding,
                content);
        }

        private static BerHeader ReadHeader(BinaryReader reader)
        {
            byte lowTag = reader.ReadByte();
            byte classNumber = (byte)((lowTag & 0xC0) >> 6); // Extract top 2 bits and shift down
            bool primitive = ((lowTag & 0x20) == 0);
            int tag = lowTag & 0x1F; // Extract bottom 5 bits
            if (tag == 0x3F)
            {
                throw new NotImplementedException("Multi-octet tag!");
            }

            // Read the length
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
            return new BerHeader(
                (Asn1Class)classNumber,
                tag,
                len,
                primitive ?
                    Asn1Encoding.PrimativeDefiniteLength :
                    (len == 0 ?
                        Asn1Encoding.ConstructedIndefiniteLength :
                        Asn1Encoding.ConstructedDefiniteLength));
        }

        private struct BerHeader
        {
            public Asn1Class Class;
            public Asn1Encoding Encoding;
            public int Tag;
            public int Length;
            
            public BerHeader(Asn1Class @class, int tag, int length, Asn1Encoding encoding) : this()
            {
                Class = @class;
                Tag = tag;
                Encoding = encoding;
                Length = length;
            }
        }
    }
}