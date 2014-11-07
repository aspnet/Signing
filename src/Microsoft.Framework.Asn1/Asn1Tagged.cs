using System;

namespace Microsoft.Framework.Asn1
{
    public class Asn1Tagged : Asn1Value
    {
        public Asn1Value Value { get; }

        public Asn1Tagged(Asn1Class @class, int tag, int length, Asn1Encoding encoding, Asn1Value value)
            : base(@class, tag, length, encoding)
        {
            Value = value;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }
    }
}