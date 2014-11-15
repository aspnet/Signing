using System;
using System.IO;
using System.Linq;
using Xunit;

namespace Microsoft.Framework.Asn1.Test
{
    public class DerWriterTests
    {
        [Fact]
        public void WriterCanWriteLowTagHeader()
        {
            // Arrange
            byte[] data = new byte[0x0A];
            new Random().NextBytes(data);
            var val = new Asn1OctetString(data);
            var expected = WrapData(new byte[] { 0x04, 0x0A }, data);

            // Act
            var actual = WriteValue(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void WriterCanWriteHighTagHeader()
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
            var actual = WriteValue(val);

            // Assert
            Assert.Equal(expected, actual);
        }

        private byte[] WriteValue(Asn1OctetString val)
        {
            using (var stream = new MemoryStream())
            {
                var writer = new DerWriter(stream);
                writer.WriteValue(val);
                stream.Flush();
                return stream.ToArray();
            }
        }

        private byte[] WrapData(byte[] expectedHeader, byte[] data)
        {
            return Enumerable.Concat(expectedHeader, data).ToArray();
        }
    }
}