using System;
using System.Linq;
using System.Text;
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
        public void ParserCanParseSet()
        {
            // Arrange
            // [(depth).(index)]
            var data = new byte[] {
                0x11, // [0.0] Class: Universal, Tag: Set
                0x07,  // [0.0] Length of concatenated BER encodings
                0x06, // [1.0] Class: Universal, Tag: OID
                0x01, // [1.0] Length: 1 octet
                0x2A, // [1.0] Value: 1.2
                0x06, // [1.1] Class: Universal, Tag: OID
                0x02, // [1.1] Length: 2 octets
                0x2B, // [1.1]
                0x06  // [1.1] Value: 1.3.6
            };
            var expected = new Asn1Set(
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
                0xAF, // [0.0] Class: Context-Specific, Tag: 15
                0x03,  // [0.0] Length of inner BER encoding
                0x06, // [1.0] Class: Universal, Tag: OID
                0x01, // [1.0] Length: 1 octet
                0x2A, // [1.0] Value: 1.2
            };
            var expected = new Asn1TaggedConstructed(
                @class: Asn1Class.ContextSpecific,
                tag: 15,
                values: new[] { new Asn1Oid(1, 2) });

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

        [Theory]
        [InlineData(new byte[] { 0x05, 0x00 })]
        [InlineData(new byte[] { 0x05, 0x81, 0x00 })]
        [InlineData(new byte[] { 0x05, 0x82, 0x00, 0x00 })]
        public void ParseCanParseNulls(byte[] data)
        {
            // Arrange
            // This time, we put the header in the input data because the length octets are the only thing that varies anyway :)

            // Act
            var actual = ParseValue(data);

            // Assert
            Assert.Equal(Asn1Null.Instance, actual);
            Assert.Same(Asn1Null.Instance, actual); // We should even get the same instance!
        }

        [Fact]
        public void ParseCanParsePrimitiveOctetStrings()
        {
            // Arrange
            var expected = new Asn1OctetString(new byte[] { 0x01, 0x02, 0x03 });
            var data = PrependHeader(expected.Value, Asn1Constants.Tags.OctetString);

            // Act
            var actual = ParseValue(data);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(new byte[] { 0x39, 0x31, 0x30, 0x35, 0x30, 0x36, 0x32, 0x33, 0x34, 0x35, 0x34, 0x30, 0x5a }, "1991-05-06T23:45:40Z")]
        public void ParseCanParseUTCTimes(byte[] data, string dateTimeOffset)
        {
            // Arrange
            data = PrependHeader(data, Asn1Constants.Tags.UtcTime);
            var expected = new Asn1UtcTime(DateTimeOffset.Parse(dateTimeOffset));

            // Act
            var actual = ParseValue(data);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(new byte[] { 0x00, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x2C, 0x00, 0x20, 0x00, 0x57, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x6C, 0x00, 0x64, 0x00, 0x21 }, "Hello, World!", Asn1StringType.BmpString, 0x1E /* BmpString */)]
        [InlineData(new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21 }, "Hello, World!", Asn1StringType.UTF8String, 0x0C /* UTF8String */)]
        [InlineData(new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21 }, "Hello, World!", Asn1StringType.PrintableString, 0x13 /* PrintableString */)]
        public void ParseCanParseStrings(byte[] data, string str, Asn1StringType type, int tag)
        {
            // Arrange
            data = PrependHeader(data, tag);
            var expected = new Asn1String(str, type);

            // Act
            var actual = ParseValue(data);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(new byte[] { 0x06, 0xB6, 0xC0 }, "1011011011")]
        [InlineData(new byte[] { 0x06, 0xB6, 0xC1 }, "1011011011")]
        [InlineData(new byte[] { 0x06, 0xB6, 0xC2 }, "1011011011")]
        [InlineData(new byte[] { 0x06, 0x6e, 0x5d, 0xc0 }, "011011100101110111")]
        [InlineData(new byte[] { 0x06, 0x6e, 0x5d, 0xe0 }, "011011100101110111")]
        public void ParseCanParseBitStrings(byte[] data, string bitstring)
        {
            // Arrange
            data = PrependHeader(data, Asn1Constants.Tags.BitString);

            // Generate the bitstring
            
            var expected = Asn1BitString.Parse(bitstring);

            // Act
            var actual = ParseValue(data);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(new byte[] { 0x01 }, true)]
        [InlineData(new byte[] { 0x02 }, true)]
        [InlineData(new byte[] { 0x42 }, true)]
        [InlineData(new byte[] { 0x56 }, true)]
        [InlineData(new byte[] { 0xAF }, true)]
        [InlineData(new byte[] { 0x00 }, false)]
        public void ParseCanParseBooleans(byte[] data, bool value)
        {
            // Arrange
            data = PrependHeader(data, Asn1Constants.Tags.Boolean);
            var expected = new Asn1Boolean(value);

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