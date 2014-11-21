using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace Microsoft.Framework.Asn1
{
    public class Asn1BitString : Asn1Value
    {
        private byte[] _normalizedBytes;
        private string _bitString;

        public IReadOnlyCollection<byte> Bytes { get { return _normalizedBytes; } }
        public int Padding { get; }
        public int BitCount { get { return (Bytes.Count * 8) - Padding; } }

        public Asn1BitString(byte[] bytes, int padding) : this(Asn1Class.Universal, Asn1Constants.Tags.BitString, bytes, padding) { }

        public Asn1BitString(Asn1Class @class, int tag, byte[] bytes, int padding) : base(@class, tag)
        {
            Padding = padding;

            _normalizedBytes = new byte[bytes.Length];
            Array.Copy(bytes, _normalizedBytes, bytes.Length);
            if (_normalizedBytes.Length > 0 && Padding > 0)
            {
                // I suck at and dislike bit twiddling. Please do find a cleaner way to
                // set bits 0-Padding of the final octet to 0. Or just find a cleaner
                // way to store this. I care not. - anurse
                var octet = _normalizedBytes[_normalizedBytes.Length - 1];
                _normalizedBytes[_normalizedBytes.Length - 1] =
                    (byte)((octet >> Padding) << Padding);
            }

            _bitString = String.Concat(_normalizedBytes.Select(GenerateBitString));
            if (Padding > 0)
            {
                _bitString = _bitString.Substring(0, _bitString.Length - Padding);
            }
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }

        public override bool Equals(object obj)
        {
            Asn1BitString other = obj as Asn1BitString;
            return other != null &&
                base.Equals(other) &&
                Bytes.SequenceEqual(other.Bytes);
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start().Add(base.GetHashCode()).Add(_normalizedBytes);
        }

        public override string ToString()
        {
            return base.ToString() + " BIT STRING " + _bitString;
        }

        public static Asn1BitString Parse(string bits)
        {
            int padding = bits.Length % 8;
            byte[] bytes = new byte[(bits.Length / 8) + 1];
            for (int i = 0; i < bytes.Length; i++)
            {
                var len = Math.Min(8, bits.Length - (i * 8));
                var str = bits.Substring(i * 8, len);
                if (len < 8)
                {
                    str += new string('0', 8 - len);
                }
                bytes[i] = GenerateByte(str);
            }
            return new Asn1BitString(bytes, padding);
        }

        private static byte GenerateByte(string str) {
            Debug.Assert(str.Length == 8);
            return (byte)(
                (str[0] == '1' ? 0x80 : 0x00) |
                (str[1] == '1' ? 0x40 : 0x00) |
                (str[2] == '1' ? 0x20 : 0x00) |
                (str[3] == '1' ? 0x10 : 0x00) |
                (str[4] == '1' ? 0x08 : 0x00) |
                (str[5] == '1' ? 0x04 : 0x00) |
                (str[6] == '1' ? 0x02 : 0x00) |
                (str[7] == '1' ? 0x01 : 0x00));
        }

        private static string GenerateBitString(byte byt)
        {
            StringBuilder builder = new StringBuilder(8);
            builder.Append(((byt & 0x80) != 0) ? "1" : "0");
            builder.Append(((byt & 0x40) != 0) ? "1" : "0");
            builder.Append(((byt & 0x20) != 0) ? "1" : "0");
            builder.Append(((byt & 0x10) != 0) ? "1" : "0");
            builder.Append(((byt & 0x08) != 0) ? "1" : "0");
            builder.Append(((byt & 0x04) != 0) ? "1" : "0");
            builder.Append(((byt & 0x02) != 0) ? "1" : "0");
            builder.Append(((byt & 0x01) != 0) ? "1" : "0");
            return builder.ToString();
        }
    }
}