//using System;
//using System.Linq;
//using System.Collections.Generic;
//using System.Security.Cryptography.X509Certificates;

//namespace Microsoft.Framework.Signing
//{
//    public class TrustContext
//    {
//        public bool UseRootTrust { get; set; } = true;
//        public X509Certificate2Collection AdditionalTrustedRoots { get; } = new X509Certificate2Collection();
//        public IList<TrustedPublisher> TrustedPublishers { get; } = new List<TrustedPublisher>();

//        public virtual TrustResult IsTrusted(Signature signature)
//        {
//            return IsTrusted(signature.Signer, signature.Certificates);
//        }

//        public virtual TrustResult IsTrusted(Signer signer)
//        {
//            return IsTrusted(signer, includedCertificates: null);
//        }

//        public virtual TrustResult IsTrusted(Signer signer, X509Certificate2Collection includedCertificates)
//        {
//            // Build the chain
//            var chain = new X509Chain();
//            chain.ChainPolicy.VerificationFlags |= X509VerificationFlags.IgnoreEndRevocationUnknown;
//            chain.ChainPolicy.ExtraStore.AddRange(AdditionalTrustedRoots);
//            if (includedCertificates != null)
//            {
//                chain.ChainPolicy.ExtraStore.AddRange(includedCertificates);
//            }

//            // Build the chain
//            var rootTrusted = chain.Build(signer.SignerCertificate);
//            if (rootTrusted && UseRootTrust)
//            {
//                return new TrustResult(new[]
//                {
//                    TrustedPublisher.FromCertificate(chain.ChainElements[chain.ChainElements.Count - 1].Certificate)
//                });
//            }

//            // Check additionally trusted certificates to see if any in the chain exist
//            var trustedPublishers = new HashSet<TrustedPublisher>(TrustedPublishers);
//            trustedPublishers.UnionWith(AdditionalTrustedRoots.Cast<X509Certificate2>().Select(c => TrustedPublisher.FromCertificate(c)));
//            trustedPublishers.IntersectWith(chain.ChainElements.Cast<X509ChainElement>().Select(e => TrustedPublisher.FromCertificate(e.Certificate)));

//            if (trustedPublishers.Any())
//            {
//                return new TrustResult(trustedPublishers);
//            }

//            // Not trusted :(
//            return new TrustResult(Enumerable.Empty<TrustedPublisher>());
//        }
//    }
//}