using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace Microsoft.Framework.Signing
{
    internal partial class Commands
    {
        public async Task<int> Timestamp(string signature, string authority, string algorithm)
        {
            algorithm = algorithm ?? Signature.DefaultDigestAlgorithmName;

            // Load the signature
            var sig = await Signature.TryDecodeAsync(signature);

            if (!sig.IsSigned)
            {
                AnsiConsole.GetError(false).WriteLine("File is not signed: " + signature);
                return -1;
            }
            else if (sig.IsTimestamped)
            {
                AnsiConsole.GetError(false).WriteLine("File is already timestampped: " + signature + ". Only one timestamp may be applied");
                return -1;
            }

            var outConsole = AnsiConsole.GetOutput(false);

            // Timestamp the signature
            outConsole.WriteLine("Transmitting signature to timestamping authority...");
            Signer.Timestamp(sig, new Uri(authority), algorithm);

            // Write the signature back
            await sig.WriteAsync(signature);
            outConsole.WriteLine("Signature timestampped.");

            return 0;
        }
    }
}