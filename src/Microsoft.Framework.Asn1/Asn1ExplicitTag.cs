using System;

namespace Microsoft.Framework.Asn1
{
    public class Asn1ExplicitTag : Asn1Value
    {
        public Asn1Value Value { get; }

        public Asn1ExplicitTag(int tag, Asn1Value value) : this(Asn1Class.ContextSpecific, tag, value) { }
        public Asn1ExplicitTag(Asn1Class @class, int tag, Asn1Value value)
            : base(@class, tag)
        {
            Value = value;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }

        public override bool Equals(object obj)
        {
            Asn1ExplicitTag other = obj as Asn1ExplicitTag;
            return other != null &&
                base.Equals(other) &&
                Value.Equals(other.Value);
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start().Add(base.GetHashCode()).Add(Value);
        }

        public override string ToString()
        {
            return base.ToString() + " EXPLICIT { " + Value.ToString() + " }";
        }
    }
}