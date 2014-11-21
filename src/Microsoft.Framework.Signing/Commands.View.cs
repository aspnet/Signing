using System;
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
            foreach (var entry in sig.Entries)
            {
                AnsiConsole.Output.WriteLine("  " +
                    entry.ContentIdentifier + " = " +
                    GetName(entry.DigestAlgorithm) + ":" +
                    Convert.ToBase64String(entry.Digest));
            }

            // Display the signature data
            if (sig.IsSigned)
            {
                AnsiConsole.Output.WriteLine("Signer Information:");
                DumpSigner(sig, sig.Signer);

                //foreach (var counterSigner in sig.CounterSigners)
                //{
                //    AnsiConsole.Output.WriteLine("");
                //    AnsiConsole.Output.WriteLine("\x1b[32;1mCountersigner Information:\x1b[30;0m");
                //    DumpSigner(sig, counterSigner);
                //}
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