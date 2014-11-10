using System;
using Xunit;

namespace Microsoft.Framework.Asn1.Test
{
    public class BerParserTests
    {
        [Theory]
        [InlineData(new byte[] { 0x06, 0x01, 0x2A }, "1.2")]
        public void ParserCanParseOidValues(byte[] data, string expectedOid)
        {
            // Arrange
            var expected = Asn1Oid.Parse(expectedOid);

            // Act
            var actual = ParseValue(data);

            // Assert
            Assert.Equal(expected, actual);
        }

        private Asn1Value ParseValue(byte[] data)
        {
            var parser = new BerParser(data);
            return parser.ReadValue();
        }
    }
}