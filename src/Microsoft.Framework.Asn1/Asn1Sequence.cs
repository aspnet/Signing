using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Framework.Asn1
{
    public class Asn1Sequence : Asn1Value
    {
        public IEnumerable<Asn1Value> Values { get; }

        public Asn1Sequence(IEnumerable<Asn1Value> values) : this(Asn1Class.Universal, Asn1Constants.Tags.Sequence, values) { }

        public Asn1Sequence(Asn1Class @class, int tag, IEnumerable<Asn1Value> values)
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
            Asn1Sequence other = obj as Asn1Sequence;
            return other != null &&
                base.Equals(other) &&
                Values.SequenceEqual(other.Values);
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start()
                .Add(base.GetHashCode())
                .Add(Values);
        }
    }
}