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
                SignatureEntry.Compute(
                    "testdata", 
                    testData, 
                    Signature.DefaultDigestAlgorithmName));

            // Assert
            var entry = sigreq.Entries.Single();
            Assert.Equal("testdata", entry.ContentIdentifier);
            Assert.Equal(hash, entry.Digest);
            Assert.Equal(1, entry.Version);
            Assert.Equal("2.16.840.1.101.3.4.2.1", entry.DigestAlgorithm); // sha256 OID
        }

        private byte[] GenerateTestData()
        {
            var data = new byte[256];
            new Random().NextBytes(data);
            return data;
        }
    }
}