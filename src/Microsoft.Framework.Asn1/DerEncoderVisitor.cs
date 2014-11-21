using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Microsoft.Framework.Asn1
{
    internal class DerEncoderVisitor : Asn1Visitor, IDisposable
    {
        private static readonly Dictionary<Asn1StringType, Func<string, byte[]>> _encoders = new Dictionary<Asn1StringType, Func<string, byte[]>>() {
            { Asn1StringType.BmpString, str => Encoding.BigEndianUnicode.GetBytes(str) },
            { Asn1StringType.UTF8String, str => Encoding.UTF8.GetBytes(str) },
            { Asn1StringType.PrintableString, str => Encoding.ASCII.GetBytes(str) }
        };

        private DerEncoderVisitorState _state;

        private BinaryWriter Writer { get { return _state.Writer; } }

        public DerEncoderVisitor()
        {
            _state = new DerEncoderVisitorState();
        }

        private IDisposable PushState()
        {
            DerEncoderVisitorState old = _state;
            _state = new DerEncoderVisitorState();
            return new DisposableAction(() => {
                _state.Dispose();
                _state = old;
            });
        }

        public static byte[] Encode(IEnumerable<Asn1Value> values)
        {
            using (var visitor = new DerEncoderVisitor())
            {
                foreach (var value in values)
                {
                    value.Accept(visitor);
                }
                return visitor.GetEncoded();
            }
        }

        public static byte[] Encode(Asn1Value value)
        {
            return Encode(new[] { value });
        }

        public byte[] GetEncoded()
        {
            return _state.ToArray();
        }

        public override void Visit(Asn1Null value)
        {
            Write(value); // No contents to write!
        }

        public override void Visit(Asn1Boolean value)
        {
            Write(value, new[] { value.Value ? (byte)0x01 : (byte)0x00 });
        }

        public override void Visit(Asn1OctetString value)
        {
            Write(value, value.Value);
        }

        public override void Visit(Asn1BitString value)
        {
            Write(value, () =>
            {
                Writer.Write(value.Padding);
                foreach (var octet in value.Bytes)
                {
                    Writer.Write(octet);
                }
            });
        }

        public override void Visit(Asn1String value)
        {
            Write(value, () =>
            {
                Writer.Write(Asn1String.GetEncoding(value.Type).GetBytes(value.Value));
            });
        }

        public override void Visit(Asn1UtcTime value)
        {
            Write(value, () =>
            {
                Writer.Write(
                    Encoding.ASCII.GetBytes(
                        value.Value.UtcDateTime.ToString("yyMMddHHmmss") + "Z"));
            });
        }

        public override void Visit(Asn1Integer value)
        {
            Write(value, value.Value.ToByteArray().Reverse().ToArray());
        }

        public override void Visit(Asn1Oid value)
        {
            Write(value, () =>
            {
                // Write the first two subidentifiers of the OID
                Writer.Write((byte)((40 * value.Subidentifiers[0]) + value.Subidentifiers[1]));

                // Now, iterate over the remaining subidentifiers
                if (value.Subidentifiers.Count > 2)
                {
                    foreach (var subidentifier in value.Subidentifiers.Skip(2))
                    {
                        // Write the identifier as a variable-length integer
                        WriteVariableLengthInteger(subidentifier);
                    }
                }
            });
        }

        public override void Visit(Asn1SequenceBase value)
        {
            Write(value, () =>
            {
                foreach (var subvalue in value.Values)
                {
                    subvalue.Accept(this);
                }
            });
        }

        public void Dispose()
        {
            _state.Dispose();
            Writer.Dispose();
        }

        private byte[] WriteContents(Action act)
        {
            byte[] contents;
            using (PushState())
            {
                act();
                contents = GetEncoded();
            }
            return contents;
        }

        private void WriteHeader(Asn1Value value, int length)
        {
            WriteTag(value.Class, value.Tag);
            WriteLength(length);
        }

        private void Write(Asn1Value value, Action contentWriter)
        {
            var contents = WriteContents(contentWriter);
            Write(value, contents);
        }

        private void Write(Asn1Value value, ICollection<byte> contents = null)
        {
            WriteHeader(value, contents == null ? 0 : contents.Count);
            if (contents != null)
            {
                foreach (var octet in contents)
                {
                    Writer.Write(octet);
                }
            }
        }

        private void WriteTag(Asn1Class @class, int tag)
        {
            // Take the last 2 bits of the class and shift them left 6 positions, to bits 8 and 7
            // 0b0000_0011 => 0b1100_0000
            byte octet = (byte)((((byte)@class) & 0x03) << 6);

            // Check the format of the tag
            if (tag >= 0x1F)
            {
                // Write the class and a marker to indicate high-format tag

                // Add 0x1F to mark the tag as high-format
                octet += 0x1F;
                Writer.Write(octet);

                WriteVariableLengthInteger(tag);
            }
            else
            {
                // Low tag format => Bits 7 and 8 are class, 6 is primative/constructed flag, 5-1 are tag

                // Add bits 5-1 of the tag to the octet
                // Tag = 0x10 = 0b0001_0000, Class = 0b11 => 0b1101_0000
                octet += (byte)(tag & 0x1F);

                // Write the tag!
                Writer.Write(octet);
            }
        }

        private void WriteVariableLengthInteger(long value)
        {
            // Generate the list of digits in reverse order
            var digits = GenerateBaseNDigits(value, @base: 128);

            // Write all but the last digit with bit 8 set to 1
            if (digits.Count > 1)
            {
                Writer.Write(digits.Take(digits.Count - 1).Select(d => (byte)((d & 0x7F) + 0x80)).ToArray());
            }

            // Write the last digit with bit 8 set to 0
            Writer.Write((byte)(digits.Last() & 0x7F));
        }

        private static List<byte> GenerateBaseNDigits(long value, int @base)
        {
            List<byte> digits = new List<byte>();
            while ((value > @base) || (value < -(@base - 1)))
            {
                var digit = (int)(value % @base);
                value = value / @base;

                // Insert at the front so we "unreverse" the digits as we calculate them
                digits.Insert(0, (byte)digit);
            }
            digits.Insert(0, (byte)value);

            return digits;
        }

        private void WriteLength(int length)
        {
            // DER encoding requires that we use the most compact form possible.
            // So, if length is less than or equal to 0x7F, we use the short form
            if (length <= 0x7F)
            {
                // Write bits 7-1 of the length (bit 8 must be 0)
                Writer.Write((byte)(length & 0x7F));
            }
            else
            {
                var digits = GenerateBaseNDigits(length, @base: 256);

                if (digits.Count > 127)
                {
                    throw new InvalidOperationException("Length too long for definite form!");
                }

                // Write the number of digits with bit 8 set to 1
                Writer.Write((byte)((digits.Count & 0x7F) | 0x80));

                // Write the digits
                foreach (var digit in digits)
                {
                    Writer.Write(digit);
                }
            }
        }

        private class DerEncoderVisitorState : IDisposable
        {
            public MemoryStream Stream { get; }
            public BinaryWriter Writer { get; }

            public DerEncoderVisitorState()
            {
                Stream = new MemoryStream();
                Writer = new BinaryWriter(Stream);
            }

            public byte[] ToArray()
            {
                return Stream.ToArray();
            }

            public void Dispose()
            {
                Writer.Dispose();
                Stream.Dispose();
            }
        }
    }
}