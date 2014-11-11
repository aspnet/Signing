using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PackageSigning
{
    internal static class CryptoExtensions
    {
        public static string ComputePublicKeyIdentifier(this X509Certificate2 self, HashAlgorithm algorithm)
        {
            return Convert.ToBase64String(algorithm.ComputeHash(self.GetPublicKey()));
        }
    }
}