using System;

namespace Microsoft.Framework.Asn1
{
    public class Asn1UtcTime : Asn1Value
    {
        public DateTimeOffset Value { get; }

        public Asn1UtcTime(DateTimeOffset value)
            : this(Asn1Class.Universal, Asn1Constants.Tags.UTCTime, value)
        {
        }

        public Asn1UtcTime(Asn1Class @class, int tag, DateTimeOffset value)
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
            Asn1UtcTime other = obj as Asn1UtcTime;
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
            return base.ToString() + " UTCTime " + Value.ToString("O");
        }
    }
}