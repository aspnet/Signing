using System;
using System.Threading.Tasks;

namespace Microsoft.Framework.Signing
{
    internal static partial class Commands
    {
        public static async Task<int> CreateSigningRequest(string fileName, string outputFile, string digestAlgorithm)
        {
            // Set default values
            outputFile = outputFile ?? (fileName + ".sigreq");
            digestAlgorithm = digestAlgorithm ?? Signature.DefaultDigestAlgorithmName;

            // Create the signature
            var sig = new Signature(SignatureEntry.Compute(fileName, digestAlgorithm));

            // Write the unsigned request
            await sig.WriteAsync(outputFile);

            return 0;
        }
    }
}