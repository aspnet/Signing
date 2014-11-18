using System;
using System.Security.Cryptography.X509Certificates;

namespace PackageSigning
{
    public class TrustedPublisher
    {
        public string Name { get; }
        public string Spki { get; }
        public X509Certificate2 Certificate { get; }

        public TrustedPublisher(string name, string spki) : this(name, spki, certificate: null) { }
        public TrustedPublisher(string name, string spki, X509Certificate2 certificate)
        {
            Name = name;
            Spki = spki;
            Certificate = certificate;
        }

        public static TrustedPublisher FromCertificate(X509Certificate2 certificate)
        {
            return new TrustedPublisher(
                certificate.Subject,
                certificate.ComputePublicKeyIdentifier(),
                certificate);
        }

        public override bool Equals(object obj)
        {
            TrustedPublisher other = obj as TrustedPublisher;
            return other != null && string.Equals(Spki, other.Spki, StringComparison.Ordinal);
        }

        public override int GetHashCode()
        {
            return Spki.ToLowerInvariant().GetHashCode();
        }
    }
}