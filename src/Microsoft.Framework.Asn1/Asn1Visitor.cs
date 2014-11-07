namespace Microsoft.Framework.Asn1
{
    public abstract class Asn1Visitor
    {
        public virtual void Visit(Asn1Value value)
        {
        }

        public virtual void Visit(Asn1Unknown value)
        {
        }

        public virtual void Visit(Asn1Sequence value)
        {
        }

        public virtual void Visit(Asn1Oid value)
        {
        }

        public virtual void Visit(Asn1Tagged value)
        {
        }
    }
}