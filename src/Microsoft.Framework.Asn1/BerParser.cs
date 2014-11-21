using System;
using System.Linq;
using System.IO;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Framework.Asn1
{
    using System.Globalization;
    using System.Numerics;
    using Subparser = Func<BerParser, BerHeader, Asn1Value>;

    public class BerParser
    {
        private BinaryReader _reader;
        private bool _eof = false;

        private static readonly Dictionary<int, Subparser> _parsers = new Dictionary<int, Subparser>()
        {
            { Asn1Constants.Tags.Sequence, (p, h) => p.ParseSequenceOrSet(h, isSet: false) },
            { Asn1Constants.Tags.Set, (p, h) => p.ParseSequenceOrSet(h, isSet: true) },
            { Asn1Constants.Tags.ObjectIdentifier, (p, h) => p.ParseOid(h) },
            { Asn1Constants.Tags.Integer, (p, h) => p.ParseInteger(h) },
            { Asn1Constants.Tags.OctetString, (p, h) => p.ParseOctetString(h) },
            { Asn1Constants.Tags.UtcTime, (p, h) => p.ParseUtcTime(h) },
            { Asn1Constants.Tags.BmpString, (p, h) => p.ParseString(h, Asn1StringType.BmpString) },
            { Asn1Constants.Tags.UTF8String, (p, h) => p.ParseString(h, Asn1StringType.UTF8String) },
            { Asn1Constants.Tags.PrintableString, (p, h) => p.ParseString(h, Asn1StringType.PrintableString) },
            { Asn1Constants.Tags.BitString, (p, h) => p.ParseBitString(h) },
            { Asn1Constants.Tags.Boolean, (p, h) => p.ParseBoolean(h) },
            { Asn1Constants.Tags.Null, (p, h) => p.ParseNull(h) }
        };

        private static readonly Dictionary<Asn1StringType, Func<byte[], string>> _decoders = new Dictionary<Asn1StringType, Func<byte[], string>>() {
            { Asn1StringType.BmpString, DecodeBmpString },
            { Asn1StringType.UTF8String, bytes => Encoding.UTF8.GetString(bytes) },
            { Asn1StringType.PrintableString, bytes => Encoding.ASCII.GetString(bytes) }
        };

        public BerParser(byte[] input)
            : this(new MemoryStream(input))
        {
        }

        public BerParser(Stream input)
            : this(new BinaryReader(input, Encoding.UTF8, leaveOpen: false))
        {
        }

        public BerParser(BinaryReader reader)
        {
            _reader = reader;
        }

        /// <summary>
        /// Reinterprets the specified tagged value as the provided type of ASN.1 value
        /// </summary>
        /// <typeparam name="T">The type of ASN.1 value to reinterpret the provided value as</typeparam>
        /// <param name="tagged">The explicitly tagged value</param>
        /// <returns>A reinterpreted version of the node</returns>
        public virtual T Reinterpret<T>(Asn1Tagged tagged) where T : Asn1Value
        {
            throw new NotImplementedException();
        }

        public virtual Asn1Value ReadValue()
        {
            if (_eof || _reader.BaseStream.Position >= _reader.BaseStream.Length)
            {
                // End-of-stream!
                _eof = true;
                return null;
            }

            // Read the tag
            var header = ReadHeader();

            if (header.Class == Asn1Class.ContextSpecific)
            {
                if (header.Constructed)
                {
                    var innerValues = ReadInnerValues(header);
                    return new Asn1TaggedConstructed(
                        header.Class,
                        header.Tag,
                        innerValues);
                }
                else
                {
                    return new Asn1TaggedPrimitive(
                        header.Class,
                        header.Tag,
                        _reader.ReadBytes(header.Length));
                }
            }

            Subparser subparser;
            if (_parsers.TryGetValue(header.Tag, out subparser))
            {
                return subparser(this, header);
            }

            // Unknown tag, but we do have enough to read this node and move on, so do that.
            return ParseUnknown(header);
        }

        private IEnumerable<Asn1Value> ReadInnerValues(BerHeader header)
        {
            // Read the inner data
            byte[] inner = _reader.ReadBytes(header.Length);

            // Load a memory stream with it and read the values
            List<Asn1Value> values = new List<Asn1Value>();
            using (var strm = new MemoryStream(inner))
            {
                var parser = new BerParser(strm);
                Asn1Value value;
                while ((value = parser.ReadValue()) != null)
                {
                    values.Add(value);
                }
            }
            return values;
        }

        private Asn1String ParseString(BerHeader header, Asn1StringType type)
        {
            var data = _reader.ReadBytes(header.Length);
            return new Asn1String(_decoders[type](data), type);
        }

        private Asn1Oid ParseOid(BerHeader header)
        {
            byte[] octets = _reader.ReadBytes(header.Length);

            // First Octet = 40*v1+v2
            int first = octets[0] / 40;
            int second = octets[0] % 40;

            List<int> segments = new List<int>();
            segments.Add(first);
            segments.Add(second);

            // Remaining octets are encoded as base-128 digits, where the highest bit indicates if more digits exist
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
                segments);
        }

        private Asn1OctetString ParseOctetString(BerHeader header)
        {
            var data = _reader.ReadBytes(header.Length);
            return new Asn1OctetString(data);
        }

        private Asn1Integer ParseInteger(BerHeader header)
        {
            var data = _reader.ReadBytes(header.Length);
            return new Asn1Integer(
                header.Class,
                header.Tag,
                new BigInteger(data.Reverse().ToArray()));
        }

        private Asn1SequenceBase ParseSequenceOrSet(BerHeader header, bool isSet)
        {
            var values = ReadInnerValues(header);
            return Asn1SequenceBase.Create(header.Class, header.Tag, values, isSet);
        }

        private Asn1Null ParseNull(BerHeader header)
        {
            // Advance past Length bytes, but ignore them
            if (header.Length > 0)
            {
                _reader.BaseStream.Seek(header.Length, SeekOrigin.Current);
            }
            return Asn1Null.Instance;
        }

        private Asn1UtcTime ParseUtcTime(BerHeader header)
        {
            var data = _reader.ReadBytes(header.Length);
            var str = Encoding.ASCII.GetString(data);

            // Try to parse a long-form date/time string
            var val = DateTimeOffset.ParseExact(str, new string[] { "yyMMddHHmmssK", "yyMMddHHmmK" }, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces);

            return new Asn1UtcTime(val);
        }

        private Asn1BitString ParseBitString(BerHeader header)
        {
            // Read the contents
            var content = _reader.ReadBytes(header.Length);

            // First octet is the number of extra bits at the end
            var extraBits = content[0];

            // Remaining octets are the bitstring
            var octets = content.Skip(1).ToArray();

            // Trim out the extra octets from the end and construct the bitstring
            return new Asn1BitString(
                header.Class,
                header.Tag,
                octets,
                extraBits);
        }

        private Asn1Value ParseBoolean(BerHeader header)
        {
            // Read the contents
            var octets = _reader.ReadBytes(header.Length);

            // Construct the value
            return new Asn1Boolean(
                header.Class,
                header.Tag,
                octets.FirstOrDefault() != 0x00);
        }

        private Asn1Value ParseUnknown(BerHeader header)
        {
            // Read the contents
            var content = _reader.ReadBytes(header.Length);

            // Construct the value!
            return new Asn1Unknown(
                header.Class,
                header.Tag,
                content);
        }

        private IEnumerable<bool> ToBools(byte b)
        {
            yield return (b & 0x80) != 0;
            yield return (b & 0x40) != 0;
            yield return (b & 0x20) != 0;
            yield return (b & 0x10) != 0;
            yield return (b & 0x08) != 0;
            yield return (b & 0x04) != 0;
            yield return (b & 0x02) != 0;
            yield return (b & 0x01) != 0;
        }

        private static string DecodeBmpString(byte[] data)
        {
            // We have to swap all the pairs of bytes
            for (int i = 0; i < data.Length; i+=2)
            {
                var temp = data[i + 1];
                data[i + 1] = data[i];
                data[i] = temp;
            }
            return Encoding.Unicode.GetString(data);
        }

        internal BerHeader ReadHeader()
        {
            byte lowTag = _reader.ReadByte();
            byte classNumber = (byte)((lowTag & 0xC0) >> 6); // Extract top 2 bits and shift down
            bool primitive = ((lowTag & 0x20) == 0);
            int tag = lowTag & 0x1F; // Extract bottom 5 bits
            if (tag == 0x1F)
            {
                tag = ReadBase128VarInt();
            }

            // Read the length
            byte lowLen = _reader.ReadByte();
            var len = lowLen & 0x7F;
            if ((lowLen & 0x80) != 0 && len != 0) // Bit 8 set and not indeterminate length?
            {
                // Len is actually the number of length octets left, each one is a base 256 "digit"
                var lengthBytes = _reader.ReadBytes(len);
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

        private int ReadBase128VarInt()
        {
            int val = 0;
            byte cur;
            do
            {
                cur = _reader.ReadByte();
                val = (val * 128) + (cur & 0x7F);
            } while ((cur & 0x80) != 0);
            return val;
        }
    }
}