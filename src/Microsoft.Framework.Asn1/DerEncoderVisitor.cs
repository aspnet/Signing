using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Microsoft.Framework.Asn1
{
    internal class DerEncoderVisitor : Asn1Visitor
    {
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
            return new DisposableAction(() => _state = old);
        }

        public static byte[] Encode(Asn1Value value)
        {
            var visitor = new DerEncoderVisitor();
            value.Accept(visitor);
            return visitor.GetEncoded();
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

        private void Write(Asn1Value value, byte[] contents = null)
        {
            WriteTag(value.Class, value.Tag);
            WriteLength(contents == null ? 0 : contents.Length);
            if (contents != null)
            {
                Writer.Write(contents);
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
                octet += (byte)0x1F;
                Writer.Write(octet);

                // Generate the list of digits in reverse order
                var digits = GenerateBaseNDigits(tag, @base: 128);

                if (digits.Count == 0)
                {
                    // Write the tag with bit 8 set to 0
                    Writer.Write((byte)(tag & 0x7F));
                }
                else
                {
                    // Write all but the last digit with bit 8 set to 1
                    if (digits.Count > 1)
                    {
                        Writer.Write(digits.Take(digits.Count - 1).Select(d => (byte)((d & 0x7F) + 0x80)).ToArray());
                    }
                    
                    // Write the last digit with bit 8 set to 0
                    Writer.Write((byte)(digits.Last() & 0x7F));
                }
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

        private static List<byte> GenerateBaseNDigits(int value, int @base)
        {
            List<byte> digits = new List<byte>();
            do
            {
                var digit = value % @base;
                value = value / @base;

                // Insert at the front so we "unreverse" the digits as we calculate them
                digits.Insert(0, (byte)digit);
            } while (value > @base);
            digits.Add((byte)value);
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