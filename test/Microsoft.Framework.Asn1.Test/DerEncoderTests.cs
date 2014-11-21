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
            var expected = WrapData(new byte[] { 0x04, 0x0A }, data);

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
            var expected = WrapData(new byte[] {
                0x9F, // Class = Context-Specific, Tag is High-Tag Number Form
                0x88, // First digit is 8 (bits 1-7 = 0x8), there are additional digits (bit 8 = 1)
                0x0B, // Second digit is B (bits 1-7 = 0xB), there are no additional digits (bit 8 = 0)
                0x0A  // Length = 0x0A
            }, data);

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
            var expected = WrapData(new byte[] {
                0x04, // Class & Tag
                0x82, // Long-form length, 2 digits
                0x02, // First base256 length digit
                0x01  // Second base256 length digit
            }, data);

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
            var expected = WrapData(new byte[] {
                0x02,               // INTEGER tag
                (byte)bytes.Length  // Length
            }, bytes);
            var val = new Asn1Integer(integer);

            // Act
            var actual = DerEncoder.Encode(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        private byte[] WrapData(byte[] expectedHeader, byte[] data)
        {
            return Enumerable.Concat(expectedHeader, data).ToArray();
        }
    }
}