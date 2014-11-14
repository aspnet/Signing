using System;
using System.Linq;
using System.Text;

namespace Microsoft.Framework.Asn1
{
    public class Asn1String : Asn1Value
    {
        public string Value { get; }
        public Asn1StringType Type { get; }

        public Asn1String(string value, Asn1StringType type)
            : this(Asn1Class.Universal, Asn1Constants.Tags.OctetString, value, type)
        {
        }

        public Asn1String(Asn1Class @class, int tag, string value, Asn1StringType type)
            : base(@class, tag)
        {
            Value = value;
            Type = type;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }

        public override bool Equals(object obj)
        {
            Asn1String other = obj as Asn1String;
            return other != null &&
                base.Equals(other) &&
                Type == other.Type &&
                String.Equals(Value, other.Value, StringComparison.Ordinal);
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start().Add(base.GetHashCode()).Add(Type).Add(Value);
        }

        public override string ToString()
        {
            return base.ToString() + "  " + Type.ToString().ToUpper() + " " + Value;
        }
    }

    public enum Asn1StringType
    {
        BmpString,
        UTF8String,
        PrintableString
    }
}