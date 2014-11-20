using System;

namespace Microsoft.Framework.Asn1
{
    public class Asn1Integer : Asn1Value
    {
        public long Value { get; }

        public Asn1Integer(long value)
            : this(Asn1Class.Universal, Asn1Constants.Tags.Integer, value)
        {
        }

        public Asn1Integer(Asn1Class @class, int tag, long value)
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
            Asn1Integer other = obj as Asn1Integer;
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
            return base.ToString() + " INTEGER " + Value.ToString();
        }
    }
}