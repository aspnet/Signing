using System;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Xunit;
using System.Threading.Tasks;

namespace Microsoft.Framework.Signing.Test
{
    public class SignatureTests
    {
        private const string TestPassword = "test";
        private static readonly string CertRoot = Path.GetFullPath("certs");
        private static readonly string TestAuthorityCertPath = Path.Combine(CertRoot, "ca.pfx");
        private static readonly string TestSigningCertPath = Path.Combine(CertRoot, "signing.pfx");
        private static readonly string TestTimestampingCertPath = Path.Combine(CertRoot, "timestamping.pfx");

        private static X509Certificate2 GetCert(string path)
        {
            return new X509Certificate2(path, password: TestPassword);
        }

        private static X509Certificate2Collection GetAllCerts(string path)
        {
            var certs = new X509Certificate2Collection();
            certs.Import(path, TestPassword, X509KeyStorageFlags.DefaultKeySet);
            return certs;
        }

        [Fact]
        public void SignGeneratesSignatureForFileFromProvidedCertificate()
        {
            // Arrange
            var file = CreateTestData("test file!");
            var cert = GetCert(TestSigningCertPath);
            var addlCerts = GetAllCerts(TestSigningCertPath);

            // Act
            var signature = Signature.Sign(file, cert, addlCerts);

            // Assert
            Assert.Equal(GetCert(TestSigningCertPath).Subject, signature.Signer.Subject);
            Assert.Equal(GetCert(TestSigningCertPath).ComputePublicKeyIdentifier(), signature.Signer.Spki);
        }

        [Fact]
        public void SignEmbedsEntireCertificateChainInKeyInfo()
        {
            // Arrange
            var file = CreateTestData("test file!");
            var cert = GetCert(TestSigningCertPath);
            var addlCerts = GetAllCerts(TestSigningCertPath);

            // Act
            var signature = Signature.Sign(file, cert, addlCerts);

            // Assert
            Assert.Equal(2, signature.Signer.Certificates.Cast<X509Certificate2>().Count());

            var authority = signature.Signer.Certificates.Cast<X509Certificate2>().FirstOrDefault(c => !Equals(c, signature.Signer.SignerCertificate));
            Assert.NotNull(authority);
            Assert.Equal(GetCert(TestAuthorityCertPath).Subject, authority.Subject);
        }

        [Fact]
        public void WriteCreatesSignatureThatCanBeVerified()
        {
            // Arrange
            var file = CreateTestData("test file!");
            var cert = GetCert(TestSigningCertPath);
            var addlCerts = GetAllCerts(TestSigningCertPath);
            var signature = Signature.Sign(file, cert, addlCerts);

            // Act
            var sigbytes = signature.ToByteArray();

            // Assert
            var verified = Signature.Verify(file, sigbytes);
            var authority = signature.Signer.Certificates.Cast<X509Certificate2>().FirstOrDefault(c => !Equals(c, signature.Signer.SignerCertificate));

            Assert.NotNull(authority);
            Assert.Equal(2, verified.Signer.Certificates.Cast<X509Certificate2>().Count());
            Assert.Equal(GetCert(TestSigningCertPath).Subject, verified.Signer.Subject);
            Assert.Equal(GetCert(TestSigningCertPath).ComputePublicKeyIdentifier(), verified.Signer.Spki);
            Assert.Equal(GetCert(TestAuthorityCertPath).Subject, authority.Subject);
        }

        private static byte[] CreateTestData(string content)
        {
            var file = new MemoryStream();
            using (var writer = new StreamWriter(file, Encoding.UTF8, bufferSize: 1024, leaveOpen: true))
            {
                writer.Write(content);
                writer.Flush();
            }

            return file.ToArray();
        }
    }
}
