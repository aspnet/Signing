using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Microsoft.Framework.Asn1
{
    public class DerWriter
    {
        private DerWriterVisitor _visitor;

        public DerWriter(Stream output)
            : this(new BinaryWriter(output, Encoding.UTF8, leaveOpen: false))
        {
        }

        public DerWriter(BinaryWriter writer)
        {
            _visitor = new DerWriterVisitor(writer);
        }

        public virtual void WriteValue(Asn1Value value)
        {
            value.Accept(_visitor);
        }

        private class DerWriterVisitor : Asn1Visitor
        {
            private BinaryWriter _writer;

            public DerWriterVisitor(BinaryWriter writer)
            {
                _writer = writer;
            }

            public override void Visit(Asn1Null value)
            {
                Write(value); // No contents to write!
            }

            public override void Visit(Asn1Boolean value)
            {
                Write(value, new [] { value.Value ? (byte)0x01 : (byte)0x00 });
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
                    _writer.Write(contents);
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
                    _writer.Write(octet);

                    // Generate the list of digits in reverse order
                    List<byte> digits = new List<byte>();
                    do
                    {
                        var digit = tag % 128;
                        tag = tag / 128;

                        // Insert at the front so we "unreverse" the digits as we calculate them
                        digits.Insert(0, (byte)digit);
                    } while (tag > 128);

                    if (digits.Count == 0)
                    {
                        // Write the tag with bit 8 set to 0
                        _writer.Write((byte)(tag & 0x7F));
                    }
                    else
                    {
                        // Write the first digit (which is what is left in tag) with bit 8 set to 1
                        _writer.Write((byte)((tag & 0x7F) + 0x80));

                        // Write all but the last digit with bit 8 set to 1
                        if (digits.Count > 1)
                        {
                            _writer.Write(digits.Take(digits.Count - 1).Select(d => (byte)((d & 0x7F) + 0x80)).ToArray());
                        }

                        // Write the last digit with bit 8 set to 0
                        _writer.Write((byte)(digits[digits.Count - 1] & 0x7F));
                    }
                }
                else
                {
                    // Low tag format => Bits 7 and 8 are class, 6 is primative/constructed flag, 5-1 are tag

                    // Add bits 5-1 of the tag to the octet
                    // Tag = 0x10 = 0b0001_0000, Class = 0b11 => 0b1101_0000
                    octet += (byte)(tag & 0x1F);

                    // Write the tag!
                    _writer.Write(octet);
                }
            }

            private void WriteLength(int length)
            {
                // DER encoding requires that we use the most compact form possible.
                // So, if length is less than or equal to 0x7F, we use the short form
                if (length <= 0x7F)
                {
                    // Write bits 7-1 of the length (bit 8 must be 0)
                    _writer.Write((byte)(length & 0x7F));
                }
                else
                {
                    throw new NotImplementedException("Long-form length");
                }
            }
        }
    }
}