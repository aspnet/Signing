using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Xunit;

namespace PackageSigning.Test
{
    public class FileSignatureTest
    {
        [Fact]
        public void SignGeneratesSignatureForFileFromProvidedCertificate()
        {
            // Arrange
            var file = new MemoryStream();
            using (var writer = new StreamWriter(file, Encoding.UTF8, bufferSize: 1024, leaveOpen: true))
            {
                writer.Write("test file!");
                writer.Flush();
            }
            var cert = new X509Certificate2(Path.Combine("certs", "test.signing.pfx"), "test");

            // Act
            var signature = FileSignature.Sign(file, cert);

            // Assert
            Assert.Equal("CN=PackageSigning Test Signing Certficiate", signature.Signer.Subject);
            Assert.Equal("123abc", signature.Signer.Spki);
        }
    }
}