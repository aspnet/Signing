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
            var data = new Asn1OctetString(new byte[] { 0x01, 0x02, 0x03 });

            using (var fileStream = new FileStream(args[0], FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                await DerEncoder.WriteAsync(data, fileStream);
            }
        }
    }
}
