using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Framework.Asn1
{
    public class Asn1UnknownPrimitive : Asn1Value
    {
        public byte[] Content { get; }

        public Asn1UnknownPrimitive(Asn1Class @class, int tag, byte[] content)
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
            return base.ToString() + " UNKNOWN PRIMITIVE";
        }

        public override bool Equals(object obj)
        {
            Asn1UnknownPrimitive other = obj as Asn1UnknownPrimitive;
            return other != null &&
                base.Equals(other) &&
                Content.SequenceEqual(other.Content);
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start().Add(base.GetHashCode()).Add(Content);
        }
    }

    public class Asn1UnknownConstructed : Asn1Value
    {
        public IEnumerable<Asn1Value> Values { get; }

        public Asn1UnknownConstructed(Asn1Class @class, int tag, IEnumerable<Asn1Value> values)
            : base(@class, tag)
        {
            Values = values;
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }

        public override bool Equals(object obj)
        {
            Asn1UnknownConstructed other = obj as Asn1UnknownConstructed;
            return other != null &&
                base.Equals(other) &&
                Values.SequenceEqual(other.Values);
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start().Add(base.GetHashCode()).Add(Values);
        }

        public override string ToString()
        {
            return base.ToString() + " UNKNOWN CONSTRUCTED { " + String.Join(",", Values.Select(v => v.ToString())) + "}";
        }
    }
}