using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace Microsoft.Framework.Asn1
{
    public class Program
    {
        public async Task Main(string[] args)
        {
            await TestDecode(args);

            //await TestEncode(args);
        }

        private Task TestDecode(string[] args)
        {
            using (var fileStream = new FileStream(args[0], FileMode.Open, FileAccess.Read, FileShare.None))
            {
                var parser = new BerParser(fileStream);
                var value = parser.ReadValue();
                var visitor = new PrettyPrintingAsn1Visitor(AnsiConsole.Output.Writer, ansi: true);
                value.Accept(visitor);
            }
            return Task.FromResult(0);
        }

        private static async Task TestEncode(string[] args)
        {
            var data = new Asn1OctetString(new byte[] { 0x01, 0x02, 0x03 });

            using (var fileStream = new FileStream(args[0], FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                await DerEncoder.WriteAsync(data, fileStream);
            }
        }
    }
}
