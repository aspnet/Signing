using System;

namespace Microsoft.Framework.Asn1
{
    public class Asn1Unknown : Asn1Value
    {
        public byte[] Content { get; }

        public Asn1Unknown(Asn1Class @class, int tag, int length, Asn1Encoding encoding, byte[] content)
            : base(@class, tag, length, encoding)
        {
            Content = content;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }
    }
}