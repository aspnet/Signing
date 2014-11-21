using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Framework.Asn1
{
    public static class DerEncoder
    {
        public static byte[] Encode(IEnumerable<Asn1Value> values)
        {
            return DerEncoderVisitor.Encode(values);
        }

        public static byte[] Encode(Asn1Value value)
        {
            return DerEncoderVisitor.Encode(value);
        }

        public static Task WriteAsync(Asn1Value value, Stream stream)
        {
            var encoded = Encode(value);
            return stream.WriteAsync(encoded, 0, encoded.Length);
        }
    }
}