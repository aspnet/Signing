using System;
using System.Linq;
using Xunit;

namespace Microsoft.Framework.Asn1.Test
{
    public class BerParserTests
    {
        // Header parsing tests
        [Fact]
        public void ParserCanAcceptLowTagNumberFormTags()
        {
            // Arrange
            var data = new byte[] { 0x06, 0x01, 0x2A };

            // Act
            var actual = ParseValue(data);

            // Assert
            Assert.Equal(Asn1Oid.Parse("1.2"), actual);
        }

        [Fact]
        public void ParserCanAcceptHighTagNumberFormTags()
        {
            // Arrange
            // Tag is 0x82, 0x04 => (2 * 128) + 4 = 260
            // Class is 0x1F => High Tag form (0x1F (indicates high tag form) & 0x00 (Universal))
            var data = new byte[] { 0x1F, 0x82, 0x04, 0x01, 0x2A };

            // Act
            var actual = ParseValue(data);

            // Assert
            Assert.Equal(Asn1Class.Universal, actual.Class);
            Assert.Equal(260, actual.Tag);
        }

        [Fact]
        public void ParserCanAcceptShortFormLength()
        {
            // Arrange
            // Only up to and including "0x2A" should be read.
            var data = new byte[] { 0x06, 0x01, 0x2A, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 };

            // Act
            var actual = ParseValue(data);

            // Assert
            Assert.Equal(Asn1Oid.Parse("1.2"), actual);
        }

        [Fact]
        public void ParserCanAcceptLongFormLength()
        {
            // Arrange
            // Only up to and including "0x2A" should be read.
            // Length is 0x82, 0x00, 0x01 => 0x82 (long-form, 2 octets), 0x00 (first digit 0), 0x01 (second digit 1) => 1 octet long
            var data = new byte[] { 0x06, 0x82, 0x00, 0x01, 0x2A, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 };

            // Act
            var actual = ParseValue(data);

            // Assert
            Assert.Equal(Asn1Oid.Parse("1.2"), actual);
        }

        [Theory]
        [InlineData(new byte[] { 0x2A }, "1.2")]
        [InlineData(new byte[] { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 }, "1.3.6.1.5.5.7.3.3")]
        public void ParserCanParseOidValues(byte[] oidData, string expectedOid)
        {
            // Arrange
            // Construct the header (we're not testing header parsing)
            var tag = Asn1Constants.Tags.ObjectIdentifier;
            byte[] data = PrependHeader(oidData, tag);
            var expected = Asn1Oid.Parse(expectedOid);

            // Act
            var actual = ParseValue(data);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void ParserCanParseSequence()
        {
            // Arrange
            // [(depth).(index)]
            var data = new byte[] {
                0x10, // [0.0] Class: Universal, Tag: Sequence
                0x07,  // [0.0] Length of concatenated BER encodings
                0x06, // [1.0] Class: Universal, Tag: OID
                0x01, // [1.0] Length: 1 octet
                0x2A, // [1.0] Value: 1.2
                0x06, // [1.1] Class: Universal, Tag: OID
                0x02, // [1.1] Length: 2 octets
                0x2B, // [1.1]
                0x06  // [1.1] Value: 1.3.6
            };
            var expected = new Asn1Sequence(
                new Asn1Oid(1, 2),
                new Asn1Oid(1, 3, 6));

            // Act
            var actual = ParseValue(data);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void ParserCanParseExplicitlyTaggedValue()
        {
            // Arrange
            // [(depth).(index)]
            var data = new byte[] {
                0x8F, // [0.0] Class: Context-Specific, Tag: 15
                0x03,  // [0.0] Length of inner BER encoding
                0x06, // [1.0] Class: Universal, Tag: OID
                0x01, // [1.0] Length: 1 octet
                0x2A, // [1.0] Value: 1.2
            };
            var expected = new Asn1ExplicitTag(
                tag: 15,
                value: new Asn1Oid(1, 2));

            // Act
            var actual = ParseValue(data);

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
        public void ParserCanParseInteger(byte[] data, long value)
        {
            // Arrange
            data = PrependHeader(data, Asn1Constants.Tags.Integer);
            var expected = new Asn1Integer(value);

            // Act
            var actual = ParseValue(data);

            // Assert
            Assert.Equal(expected, actual);
        }

        private static byte[] PrependHeader(byte[] data, int tag)
        {
            return Enumerable.Concat(
                            new byte[] {
                    (byte)tag,
                    (byte)data.Length
                            },
                            data).ToArray();
        }

        private Asn1Value ParseValue(byte[] data)
        {
            var parser = new BerParser(data);
            return parser.ReadValue();
        }
    }
}