using System;

namespace Microsoft.Framework.Asn1
{
    public class Asn1Boolean : Asn1Value
    {
        public bool Value { get; }

        public Asn1Boolean(bool value) : this(Asn1Class.Universal, Asn1Constants.Tags.Boolean, value) { }
        public Asn1Boolean(Asn1Class @class, int tag, bool value) : base(@class, tag)
        {
            Value = value;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }

        public override bool Equals(object obj)
        {
            Asn1Boolean other = obj as Asn1Boolean;
            return other != null &&
                base.Equals(other) &&
                Value == other.Value;
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start().Add(base.GetHashCode()).Add(Value);
        }

        public override string ToString()
        {
            return base.ToString() + " BOOLEAN " + Value.ToString().ToUpperInvariant();
        }
    }
}