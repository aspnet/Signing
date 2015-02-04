using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace Microsoft.Framework.Signing
{
    internal partial class Commands
    {
        public async Task<int> Prepare(string fileName, string outputFile, string digestAlgorithm)
        {
            // Set default values
            outputFile = outputFile ?? (fileName + ".req");
            digestAlgorithm = digestAlgorithm ?? Signature.DefaultDigestAlgorithmName;

            if (File.Exists(outputFile))
            {
                AnsiConsole.Error.WriteLine("Signature request already exists: " + outputFile);
                return 1;
            }

            // Create the signature
            AnsiConsole.Output.WriteLine("Computing Signature Request...");
            var sig = Signer.Prepare(fileName, digestAlgorithm);
            AnsiConsole.Output.WriteLine("Signature request written to " + outputFile);

            // Write the unsigned request
            await sig.WriteAsync(outputFile);

            return 0;
        }
    }
}