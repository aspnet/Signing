using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace Microsoft.Framework.Signing.Test
{
    public class SignerTests
    {
        public class ThePrepareMethod
        {
            [Fact]
            public void Creates_Signature_Request_With_Expected_Payload()
            {
                // Arrange
                var data = new byte[] { 0x01, 0x02, 0x03 };
                var expectedHash = "A5BYxvLAy0ksUzsKTRTvd8wPeKvMztUofYShogEc+4E=";
                var signer = new Signer();

                // Act
                var req = signer.Prepare("the data", data);

                // Assert
                Assert.False(req.IsSigned);
                Assert.False(req.IsTimestamped);
                Assert.Equal(req.Payload.ContentIdentifier, "the data");
                Assert.Equal(
                    req.Payload.DigestAlgorithm.Value,
                    CryptoConfig.MapNameToOID(Signature.DefaultDigestAlgorithmName));
                Assert.Equal(
                    expectedHash,
                    Convert.ToBase64String(req.Payload.Digest));
            }

            [Fact]
            public void Creates_Signature_Request_With_Specified_Digest_Algorithm()
            {
                // Arrange
                var data = new byte[] { 0x01, 0x02, 0x03 };
                var expectedHash = "cDeAcZjCKn0rCAc3HXY3eahP388=";
                var signer = new Signer();

                // Act
                var req = signer.Prepare("the data", data, "sha1");

                // Assert
                Assert.Equal(
                    req.Payload.DigestAlgorithm.Value,
                    CryptoConfig.MapNameToOID("sha1"));
                Assert.Equal(
                    expectedHash,
                    Convert.ToBase64String(req.Payload.Digest));
            }
        }

        public class TheSignMethod
        {
            [Fact]
            public void Creates_Signature()
            {
                // Arrange
                var data = new byte[] { 0x01, 0x02, 0x03 };
                var signer = new Signer();
                var sig = signer.Prepare("the data", data);
                var cert = LoadTestCert("(TEST TEST TEST) TEST Signing Certificate");

                // Act
                signer.Sign(sig, cert);

                // Assert
                Assert.True(sig.IsSigned);
                Assert.Equal("CN=(TEST TEST TEST) TEST Signing Certificate, O=NuGet Package Signing Test Certificates", sig.Signatory.SignerCertificate.Subject);
            }

            [Fact]
            public void Creates_A_Signatory_Based_On_The_Provided_Certificate()
            {
                // Arrange
                var start = DateTime.UtcNow;
                var data = new byte[] { 0x01, 0x02, 0x03 };
                var signer = new Signer();
                var sig = signer.Prepare("the data", data);
                var cert = LoadTestCert("(TEST TEST TEST) TEST Signing Certificate");

                // Act
                signer.Sign(sig, cert);

                // Assert
                Assert.Equal(cert, sig.Signatory.SignerCertificate);
                Assert.True(sig.Signatory.SigningTime.HasValue);
            }

            [Fact]
            public void Embeds_All_Certificates_In_The_Chain_In_The_Signature()
            {
                // Arrange
                var start = DateTime.UtcNow;
                var data = new byte[] { 0x01, 0x02, 0x03 };
                var signer = new Signer();
                var sig = signer.Prepare("the data", data);
                var cert = LoadTestCert("(TEST TEST TEST) TEST Signing Certificate");

                // Act
                signer.Sign(sig, cert);

                // Assert
                Assert.Equal(3, sig.Certificates.Count);

                Assert.Equal(1, sig.Certificates
                    .Find(X509FindType.FindBySubjectName, "(TEST TEST TEST) TEST Signing Certificate", validOnly: false)
                    .Count);
                Assert.Equal(1, sig.Certificates
                    .Find(X509FindType.FindBySubjectName, "(TEST TEST TEST) TEST Intermediate Certificate", validOnly: false)
                    .Count);
                Assert.Equal(1, sig.Certificates
                    .Find(X509FindType.FindBySubjectName, "(TEST TEST TEST) TEST Root Certificate", validOnly: false)
                    .Count);
            }
        }

        // TODO: Figure out automated tests for the timestamping process. We obviously would
        // rather avoid actually calling out to an RFC 3161 server...

        public static X509Certificate2 LoadTestCert(string name)
        {
            var certFile = new X509Certificate2Collection();
            certFile.Import(@"certs\certs.pfx", "test", X509KeyStorageFlags.DefaultKeySet);
            return certFile
                .Find(X509FindType.FindBySubjectName, name, validOnly: false)
                .Cast<X509Certificate2>()
                .FirstOrDefault();
        }
    }
}