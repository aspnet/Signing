using System;

namespace Microsoft.Framework.Asn1
{
    public class Asn1ExplicitTag : Asn1Value
    {
        public Asn1Value Value { get; }

        public Asn1ExplicitTag(int tag, Asn1Value value)
            : base(Asn1Class.ContextSpecific, tag)
        {
            Value = value;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }
    }
}