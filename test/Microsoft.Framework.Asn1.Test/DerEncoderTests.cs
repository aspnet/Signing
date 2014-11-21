using System;
using System.IO;
using System.Linq;
using Xunit;

namespace Microsoft.Framework.Asn1.Test
{
    public class DerEncoderTests
    {
        [Fact]
        public void WriterCanWriteLowTagHeaderAndShortFormLength()
        {
            // Arrange
            byte[] data = new byte[0x0A];
            new Random().NextBytes(data);
            var val = new Asn1OctetString(data);
            var expected = Enumerable.Concat(new byte[] { 0x04, 0x0A }, data).ToArray();

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void WriterCanWriteHighTagHeaderAndShortFormLength()
        {
            // Arrange
            byte[] data = new byte[0x0A];
            new Random().NextBytes(data);
            var val = new Asn1OctetString(Asn1Class.ContextSpecific, 1035, data);

            // Tag = 1035 = 8 * 128 + 11 = (0x08 * 0x80) + 0xB
            // In Base 128 (0x80), first digit is "0x08", second digit is "0x0B"
            var expected = Enumerable.Concat(new byte[] {
                0x9F, // Class = Context-Specific, Tag is High-Tag Number Form
                0x88, // First digit is 8 (bits 1-7 = 0x8), there are additional digits (bit 8 = 1)
                0x0B, // Second digit is B (bits 1-7 = 0xB), there are no additional digits (bit 8 = 0)
                0x0A  // Length = 0x0A
            }, data).ToArray();

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void WriterCanWriteLongFormLength()
        {
            // Arrange
            byte[] data = new byte[513];
            new Random().NextBytes(data);
            var val = new Asn1OctetString(data);
            var expected = Enumerable.Concat(new byte[] {
                0x04, // Class & Tag
                0x82, // Long-form length, 2 digits
                0x02, // First base256 length digit
                0x01  // Second base256 length digit
            }, data).ToArray();

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(new byte[] { 0x00 }, 0)]
        [InlineData(new byte[] { 0x7F }, 127)]
        [InlineData(new byte[] { 0x00, 0x80 }, 128)]
        [InlineData(new byte[] { 0x01, 0x00 }, 256)]
        [InlineData(new byte[] { 0x80 }, -128)]
        [InlineData(new byte[] { 0xFF, 0x7F }, -129)]
        [InlineData(new byte[] { 0x3A, 0x4E, 0x50, 0x70, 0xDF, 0x6C, 0x08, 0x2A }, 4201383948098209834)]
        public void WriterCanWriteInteger(byte[] bytes, long integer)
        {
            // Arrange
            var expected = WrapData(
                tag: Asn1Constants.Tags.Integer,
                content: bytes);
            var val = new Asn1Integer(integer);

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(new byte[] { 0x06, 0xB6, 0xC0 }, "1011011011")]
        [InlineData(new byte[] { 0x06, 0x6e, 0x5d, 0xc0 }, "011011100101110111")]
        public void WriterCanWriteBitString(byte[] bytes, string bitString)
        {
            // Arrange
            var expected = WrapData(
                tag: Asn1Constants.Tags.BitString,
                content: bytes);
            var val = Asn1BitString.Parse(bitString);

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void WriterCanWriteNull()
        {
            // Arrange
            var val = Asn1Null.Instance;

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(new byte[] { 0x05, 0x00 }, actual);
        }

        [Theory]
        [InlineData(new byte[] { 0x2A }, "1.2")]
        [InlineData(new byte[] { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 }, "1.3.6.1.5.5.7.3.3")]
        public void WriterCanWriteObjectIdentifier(byte[] encoded, string oid)
        {
            // Arrange
            var val = Asn1Oid.Parse(oid);
            var expected = WrapData(
                tag: Asn1Constants.Tags.ObjectIdentifier,
                content: encoded);

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(new byte[] { 0x01 }, true)]
        [InlineData(new byte[] { 0x00 }, false)]
        public void WriterCanWriteBooleans(byte[] encoded, bool value)
        {
            // Arrange
            var val = new Asn1Boolean(value);
            var expected = WrapData(
                tag: Asn1Constants.Tags.Boolean,
                content: encoded);

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(new byte[] { 0x00, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x2C, 0x00, 0x20, 0x00, 0x57, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x6C, 0x00, 0x64, 0x00, 0x21 }, "Hello, World!", Asn1StringType.BmpString, 0x1E /* BmpString */)]
        [InlineData(new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21 }, "Hello, World!", Asn1StringType.UTF8String, 0x0C /* UTF8String */)]
        [InlineData(new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21 }, "Hello, World!", Asn1StringType.PrintableString, 0x13 /* PrintableString */)]
        public void WriterCanWriteStrings(byte[] encoded, string str, Asn1StringType type, int tag)
        {
            // Arrange
            var val = new Asn1String(str, type);
            var expected = WrapData(
                tag,
                content: encoded);

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(new byte[] { 0x39, 0x31, 0x30, 0x35, 0x30, 0x36, 0x32, 0x33, 0x34, 0x35, 0x34, 0x30, 0x5a }, "1991-05-06T23:45:40Z")]
        public void WriterCanWriteUTCTimes(byte[] encoded, string dateTimeOffset)
        {
            // Arrange
            var val = new Asn1UtcTime(DateTimeOffset.Parse(dateTimeOffset));
            var expected = WrapData(
                tag: Asn1Constants.Tags.UtcTime,
                content: encoded);

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void WriterCanWriteSequenceAndSet(bool isSet)
        {
            // Arrange
            // Encode the members
            var members = new Asn1Value[] {
                new Asn1Integer(42),
                new Asn1Integer(24),
                Asn1Null.Instance
            };
            var encodedMembers = DerEncoder.Encode(members);

            // Build the expected value
            var expected = WrapData(
                tag: (isSet ? 0x11 : 0x10),
                content: encodedMembers,
                constructed: true);

            // Act
            var actual = DerEncoder.Encode(isSet ? (Asn1Value)new Asn1Set(members) : new Asn1Sequence(members));

            // Assert
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void WriterCanWriteUnknownPrimitive()
        {
            // Arrange
            var val = new Asn1UnknownPrimitive(
                Asn1Class.Private, tag: 0x1E, content: new byte[] { 0xC0, 0x01, 0xC0, 0xDE });
            var expected = Enumerable.Concat(new byte[] {
                0xC0 | 0x1E,    // Class: Private (0xC0), Primitive, Tag: 0x1E
                (byte)val.Content.Length
            }, val.Content).ToArray();

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void WriterCanWriteUnknownConstructed()
        {
            // Arrange
            var members = new Asn1Value[] {
                    new Asn1Integer(42),
                    new Asn1Integer(24),
                    Asn1Null.Instance
            };
            var encodedMembers = DerEncoder.Encode(members);
            var val = new Asn1UnknownConstructed(
                Asn1Class.Private, tag: 0x1E, values: members);
            var expected = Enumerable.Concat(new byte[] {
                0xC0 | 0x20 | 0x1E,         // Class: Private (0xC0), Constructed (0x20), Tag: 0x1E
                (byte)encodedMembers.Length
            }, encodedMembers).ToArray();

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void WriterCanWriteExplicitTaggedValue()
        {
            var val = new Asn1ExplicitTag(tag: 0x1E, value: new Asn1Integer(42));
            var expected = new byte[] {
                0x80 | 0x20 | 0x1E,                 // Class: ContextSpecific (0x80), Constructed (0x20), Tag: 0x1E
                0x03,                               // Length
                (byte)Asn1Constants.Tags.Integer,
                0x01,                               //  Length
                0x2A                                //  42 = 0x2A
            };

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        private byte[] WrapData(int tag, byte[] content, bool constructed = false)
        {
            Assert.True(tag < 31, "WrapData can only be used with tags < 31");
            Assert.True(content.Length <= 127, "WrapData can only be used with lengths <= 127");
            return Enumerable.Concat(
                new byte[] { (byte)(tag | (constructed ? 0x20 : 0x00)), (byte)content.Length },
                content).ToArray();
        }
    }
}