using System.Collections.Generic;

namespace Microsoft.Framework.Asn1
{
    public abstract class Asn1Visitor
    {
        protected int Depth { get; private set; } = 0;

        public virtual void Visit(Asn1Value value)
        {
        }

        public virtual void Visit(Asn1Unknown value)
        {
            Visit((Asn1Value)value);
        }

        public virtual void Visit(Asn1Oid value)
        {
            Visit((Asn1Value)value);
        }

        public virtual void Visit(Asn1Integer value)
        {
            Visit((Asn1Value)value);
        }

        public virtual void Visit(Asn1Null value)
        {
            Visit((Asn1Value)value);
        }

        public virtual void Visit(Asn1OctetString value)
        {
            Visit((Asn1Value)value);
        }

        public virtual void Visit(Asn1UtcTime value)
        {
            Visit((Asn1Value)value);
        }

        public virtual void Visit(Asn1String value)
        {
            Visit((Asn1Value)value);
        }

        public virtual void Visit(Asn1SequenceBase value)
        {
            Visit((Asn1Value)value);
        }

        public virtual void Visit(Asn1BitString value)
        {
            Visit((Asn1Value)value);
        }

        public virtual void Visit(Asn1Boolean value)
        {
            Visit((Asn1Value)value);
        }

        public virtual void Visit(Asn1Tagged value)
        {
            Visit((Asn1Value)value);
        }

        public virtual void Visit(Asn1TaggedConstructed value)
        {
            Visit((Asn1Tagged)value);
        }

        public virtual void Visit(Asn1TaggedPrimitive value)
        {
            Visit((Asn1Tagged)value);
        }

        public virtual void Visit(Asn1Sequence value)
        {
            Visit((Asn1SequenceBase)value);
        }

        public virtual void Visit(Asn1Set value)
        {
            Visit((Asn1SequenceBase)value);
        }

        protected void VisitSubValue(Asn1Value value)
        {
            VisitSubValues(SingleEnumerable(value));
        }

        protected void VisitSubValues(IEnumerable<Asn1Value> values)
        {
            Depth++;
            foreach (var subvalue in values)
            {
                subvalue.Accept(this);
            }
            Depth--;
        }

        private static IEnumerable<T> SingleEnumerable<T>(T item)
        {
            yield return item;
        }
    }
}