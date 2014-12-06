using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace Microsoft.Framework.Signing
{
    internal static partial class Commands
    {
        public static async Task<int> Sign(string fileName, IEnumerable<CommandOption> options)
        {
            var signOptions = SignOptions.FromOptions(fileName, options);

            var signingCert = signOptions.FindCert();
            if (signingCert == null)
            {
                AnsiConsole.Error.WriteLine("Unable to find certificate that meets the specified criteria");
                return -1;
            }
            if (!signingCert.HasPrivateKey)
            {
                AnsiConsole.Error.WriteLine("Unable to find private key for certificate: " + signingCert.Subject);
                return -1;
            }

            AnsiConsole.Output.WriteLine("Signing file with: " + signingCert.Subject);

            //// Determine if we are signing a request or a file
            //Signature sig = await Signature.TryDecodeAsync(fileName);
            //if (sig == null)
            //{
            //    sig = new Signature(SignaturePayload.Compute(fileName, Signature.DefaultDigestAlgorithmName));
            //}

            //// Verify that the content is unsigned
            //if (sig.IsSigned)
            //{
            //    AnsiConsole.Error.WriteLine("File already signed: " + fileName);
            //    return -1;
            //}

            //// Sign the file
            //sig.Sign(signingCert, certs);

            //// Write the signature
            //await sig.WriteAsync(outputFile);

            //AnsiConsole.Output.WriteLine("Successfully signed.");

            return 0;
        }
    }
}