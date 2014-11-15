using System;
using System.IO;
using Microsoft.Framework.Runtime.Common.CommandLine;

namespace Microsoft.Framework.Asn1
{
    public class Program
    {
        public void Main(string[] args)
        {
            var data = new Asn1OctetString(new byte[] { 0x01, 0x02, 0x03 });

            using (var fileStream = new FileStream(args[0], FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                var writer = new DerWriter(fileStream);
                writer.WriteValue(data);
            }
        }
    }
}
