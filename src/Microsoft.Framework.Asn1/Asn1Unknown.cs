using System;

namespace Microsoft.Framework.Asn1
{
    public class Asn1Unknown : Asn1Value
    {
        public byte[] Content { get; }

        public Asn1Unknown(Asn1Class @class, int tag, byte[] content)
            : base(@class, tag)
        {
            Content = content;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }

        public override string ToString()
        {
            return "UNKNOWN";
        }
    }
}