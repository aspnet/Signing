using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace Microsoft.Framework.Signing.Test
{
    public class SignatureTests
    {
        [Fact]
        public void ConstructorProducesUnsignedSignatureRequest()
        {
            // Arrange
            var testData = GenerateTestData();
            var hash = HashAlgorithm.Create(Signature.DefaultDigestAlgorithmName).ComputeHash(testData);

            // Act
            var sigreq = new Signature(
                SignaturePayload.Compute(
                    "testdata",
                    testData,
                    Signature.DefaultDigestAlgorithmName));

            // Assert
            Assert.Equal("testdata", sigreq.Payload.ContentIdentifier);
            Assert.Equal(hash, sigreq.Payload.Digest);
            Assert.Equal(1, sigreq.Payload.Version);
            Assert.Equal("2.16.840.1.101.3.4.2.1", sigreq.Payload.DigestAlgorithm.Value); // sha256 OID
        }

        private byte[] GenerateTestData()
        {
            var data = new byte[256];
            new Random().NextBytes(data);
            return data;
        }
    }
}