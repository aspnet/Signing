using System;

namespace Microsoft.Framework.Asn1
{
    internal struct BerHeader
    {
        public Asn1Class Class { get; }
        public Asn1Encoding Encoding { get; }
        public int Tag { get; }
        public int Length { get; }

        public BerHeader(Asn1Class @class, int tag, int length, Asn1Encoding encoding) : this()
        {
            Class = @class;
            Tag = tag;
            Encoding = encoding;
            Length = length;
        }
    }
}