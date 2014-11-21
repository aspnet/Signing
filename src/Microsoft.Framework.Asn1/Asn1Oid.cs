using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Framework.Asn1
{
    public class Asn1Oid : Asn1Value
    {
        private List<int> _segments;
        private Lazy<string> _friendlyName;

        public string Oid { get; }
        public string FriendlyName { get { return _friendlyName.Value; } }
        public IReadOnlyList<int> Subidentifiers { get { return _segments.AsReadOnly(); } }

        public Asn1Oid(params int[] segments) : this(Asn1Class.Universal, Asn1Constants.Tags.ObjectIdentifier, segments) { }
        public Asn1Oid(IEnumerable<int> segments) : this(Asn1Class.Universal, Asn1Constants.Tags.ObjectIdentifier, segments) { }

        public Asn1Oid(Asn1Class @class, int tag, IEnumerable<int> segments)
            : base(@class, tag)
        {
            _segments = segments.ToList();

            Oid = string.Join(".", _segments.Select(s => s.ToString()));
            _friendlyName = new Lazy<string>(() => GetFriendlyName(Oid));
        }

        public override void Accept(Asn1Visitor visitor)
        {
            visitor.Visit(this);
        }

        public override bool Equals(object obj)
        {
            Asn1Oid other = obj as Asn1Oid;
            return other != null &&
                base.Equals(other) &&
                _segments.SequenceEqual(other._segments);
        }

        public override int GetHashCode()
        {
            return HashCodeCombiner.Start().Add(base.GetHashCode()).Add(_segments);
        }

        public static Asn1Oid Parse(string oid)
        {
            return new Asn1Oid(ParseOid(oid));
        }

        private static IEnumerable<int> ParseOid(string oid)
        {
            return oid.Split('.').Select(p => Int32.Parse(p));
        }

        public override string ToString()
        {
            string friendlyName = String.Empty;
            if (!string.IsNullOrEmpty(FriendlyName))
            {
                friendlyName = " (" + FriendlyName + ")";
            }
            return base.ToString() + " OID " + Oid + friendlyName;
        }

        public static string GetFriendlyName(string oid)
        {
            string friendlyName;
            if (AdditionalOidTable.OidToName.TryGetValue(oid, out friendlyName))
            {
                return friendlyName;
            }
#if ASPNET50 || NET45
            try
            {
                return System.Security.Cryptography.Oid.FromOidValue(oid, System.Security.Cryptography.OidGroup.All).FriendlyName;
            }
            catch
            {
                return null;
            }
#else
            return null;
#endif
        }
    }
}