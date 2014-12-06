using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.Framework.Signing
{
    public static class CryptoExtensions
    {
        public static string ComputePublicKeyIdentifier(this X509Certificate2 self)
        {
            return ComputePublicKeyIdentifier(self, Signature.DefaultDigestAlgorithmName);
        }

        public static string ComputePublicKeyIdentifier(this X509Certificate2 self, string algorithmName)
        {
            var algorithm = (HashAlgorithm)CryptoConfig.CreateFromName(algorithmName);
            return algorithmName.ToLowerInvariant() + ":" + Convert.ToBase64String(algorithm.ComputeHash(self.GetPublicKey()));
        }

        public static bool HasEKU(this X509Certificate2 self, Oid requiredEku)
        {
            return self.Extensions
                .OfType<X509EnhancedKeyUsageExtension>()
                .SelectMany(ext => ext.EnhancedKeyUsages.Cast<Oid>())
                .Any(eku => string.Equals(requiredEku.Value, eku.Value, StringComparison.OrdinalIgnoreCase));
        }
    }
}