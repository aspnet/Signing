using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Framework.Asn1
{
    public abstract class Asn1SequenceBase : Asn1Value
    {
        public bool IsSet { get; }
        public IList<Asn1Value> Values { get; }

        protected Asn1SequenceBase(Asn1Class @class, int tag, IEnumerable<Asn1Value> values, bool isSet)
            : base(@class, tag)
        {
            Values = values.ToList();
            IsSet = isSet;
        }

        public override bool Equals(object obj)
        {
            Asn1SequenceBase other = obj as Asn1SequenceBase;
            return other != null &&
                base.Equals(other) &&
                IsSet == other.IsSet &&
                Values.SequenceEqual(other.Values);
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start()
                .Add(base.GetHashCode())
                .Add(IsSet)
                .Add(Values);
        }

        public override string ToString()
        {
            return base.ToString() + " " + (IsSet ? "SET" : "SEQUENCE") +" {" + String.Join(";", Values.Select(v => v.ToString())) + "}";
        }

        internal static Asn1SequenceBase Create(Asn1Class @class, int tag, IEnumerable<Asn1Value> values, bool isSet)
        {
            return isSet ?
                new Asn1Set(@class, tag, values) :
                (Asn1SequenceBase)new Asn1Sequence(@class, tag, values);
        }
    }

    public class Asn1Sequence : Asn1SequenceBase
    {
        public Asn1Sequence(params Asn1Value[] values) : base(Asn1Class.Universal, Asn1Constants.Tags.Sequence, values, isSet: false) { }
        public Asn1Sequence(IEnumerable<Asn1Value> values) : base(Asn1Class.Universal, Asn1Constants.Tags.Sequence, values, isSet: false) { }

        public Asn1Sequence(Asn1Class @class, int tag, IEnumerable<Asn1Value> values)
            : base(@class, tag, values, isSet: false) { }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }
    }

    public class Asn1Set : Asn1SequenceBase
    {
        public Asn1Set(params Asn1Value[] values) : base(Asn1Class.Universal, Asn1Constants.Tags.Set, values, isSet: true)
        { }
        public Asn1Set(IEnumerable<Asn1Value> values) : base(Asn1Class.Universal, Asn1Constants.Tags.Set, values, isSet: true)
        { }

        public Asn1Set(Asn1Class @class, int tag, IEnumerable<Asn1Value> values)
            : base(@class, tag, values, isSet: true) { }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }
    }
}