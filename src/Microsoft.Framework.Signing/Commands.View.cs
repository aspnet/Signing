using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace Microsoft.Framework.Signing
{
    internal static partial class Commands
    {
        public static async Task<int> View(string signatureFile)
        {
            // Verify the signature
            var sig = await Signature.TryDecodeAsync(signatureFile);

            // Display the signed files
            AnsiConsole.Output.WriteLine("Signature Payload");
            AnsiConsole.Output.WriteLine(" Version: " + sig.Payload.Version);
            AnsiConsole.Output.WriteLine(" Content Identifier: " + sig.Payload.ContentIdentifier);
            AnsiConsole.Output.WriteLine(" Digest Algorithm: " + sig.Payload.DigestAlgorithm.FriendlyName);
            AnsiConsole.Output.WriteLine(" Digest: " + BitConverter.ToString(sig.Payload.Digest).Replace("-", ""));

            // Check the digest?
            var payloadFile = Path.Combine(Path.GetDirectoryName(signatureFile), sig.Payload.ContentIdentifier);
            bool? verified = null;
            if (File.Exists(payloadFile))
            {
                verified = sig.Payload.Verify(payloadFile);
            }

            if (verified == null)
            {
                AnsiConsole.Output.WriteLine(" Unable to locate content file for verification");
            }
            else if (verified == true)
            {
                AnsiConsole.Output.WriteLine(" Content file matches signature!");
            }
            else
            {
                AnsiConsole.Output.WriteLine(" Content file does NOT match signature!");
            }

            AnsiConsole.Output.WriteLine("");

            // Display the signature data
            if (sig.IsSigned)
            {
                AnsiConsole.Output.WriteLine("Signer Information:");
                DumpSigner(sig, sig.Signer);
            }
            else
            {
                AnsiConsole.Output.WriteLine("Unsigned!");
            }

            return 0;
        }

        private static string GetName(string digestAlgorithm)
        {
#if NET45
            Oid oid;
            try
            {
                oid = Oid.FromOidValue(digestAlgorithm, OidGroup.HashAlgorithm);
            }
            catch
            {
                return digestAlgorithm;
            }
            if (String.IsNullOrEmpty(oid.FriendlyName))
            {
                return digestAlgorithm;
            }
            return oid.FriendlyName;
#else
            return digestAlgorithm;
#endif
        }

        private static void DumpSigner(Signature signature, Signer signer)
        {
            AnsiConsole.Output.WriteLine("  [Subject]");
            AnsiConsole.Output.WriteLine("    " + signer.Subject);
            AnsiConsole.Output.WriteLine("  [SPKI]");
            AnsiConsole.Output.WriteLine("    " + signer.Spki);
            AnsiConsole.Output.WriteLine("  [Issuer]");
            AnsiConsole.Output.WriteLine("    " + signer.SignerCertificate.Issuer);
            AnsiConsole.Output.WriteLine("  [Signing Time]");
            AnsiConsole.Output.WriteLine("    " + (signer.SigningTime?.ToString("O")) ?? "UNKNOWN!");
            AnsiConsole.Output.WriteLine("  [Cert Chain]");
            var chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.AddRange(signature.Certificates);
            chain.Build(signer.SignerCertificate);
            foreach (var element in chain.ChainElements)
            {
                AnsiConsole.Output.WriteLine("    " + element.Certificate.Subject);
                AnsiConsole.Output.WriteLine("      Status: " + String.Join(", ", element.ChainElementStatus.Select(s => s.Status)));
                AnsiConsole.Output.WriteLine("      Info:   " + element.Information);
                AnsiConsole.Output.WriteLine("      SPKI:   " + element.Certificate.ComputePublicKeyIdentifier());
            }
        }
    }
}