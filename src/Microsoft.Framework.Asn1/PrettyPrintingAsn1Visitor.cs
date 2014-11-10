using System;
using System.IO;
using System.Text;

namespace Microsoft.Framework.Asn1
{
    public class PrettyPrintingAsn1Visitor : Asn1Visitor
    {
        private TextWriter _output;
        private bool _ansi;
        private int? _explicitTag = null;

        public PrettyPrintingAsn1Visitor(TextWriter output, bool ansi)
        {
            _output = output;
            _ansi = ansi;
        }

        public override void Visit(Asn1Value value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            _output.WriteLine(line);
        }

        public override void Visit(Asn1SequenceBase value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            line.Append(value.IsSet ? "SET" : "SEQUENCE");
            _output.WriteLine(line);

            VisitSubValues(value.Values);
        }

        public override void Visit(Asn1Oid value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);

            line.Append("OID\t" + FormatOid(value));
            _output.WriteLine(line);
        }

        public override void Visit(Asn1Integer value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);

            line.Append("INTEGER\t" + value.Value.ToString());
            _output.WriteLine(line);
        }

        private static string FormatOid(Asn1Oid value)
        {
            var formatted = value.Oid;
#if ASPNET50 || NET45
            // On full CLR, we can use the Oid class to try and get a Friendly Name!
            try
            {
                var oid = System.Security.Cryptography.Oid.FromOidValue(value.Oid, System.Security.Cryptography.OidGroup.All);
                if (!string.IsNullOrEmpty(oid.FriendlyName))
                {
                    formatted = oid.Value + " (" + oid.FriendlyName + ")";
                }
            }
            catch // Oid.FromOidValue may throw if the OID isn't recognized :(
            {
                formatted = value.Oid;
            }
#endif
            return formatted;
        }

        public override void Visit(Asn1ExplicitTag value)
        {
            var oldTag = _explicitTag;
            _explicitTag = value.Tag;
            value.Value.Accept(this);
            _explicitTag = oldTag;
        }

        public override void Visit(Asn1Null value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            line.Append("NULL");
            _output.WriteLine(line);
        }

        public override void Visit(Asn1Unknown value)
        {
            StringBuilder line = new StringBuilder();
            BuildCommonPrefix(value, line);
            line.Append("UNKNOWN!");
            _output.WriteLine(line);
        }

        private void BuildCommonPrefix(Asn1Value value, StringBuilder line)
        {
            line.Append("  [" + Depth.ToString("00") + "]");
            line.Append(" (");

            // The longest possible string is 'Application', 11 chars long
            //  ContextSpecific is never written here because Explicit Tag nodes don't get their own line.
            line.Append(value.Class.ToString().PadLeft(11, ' ')); 

            line.Append(":");
            line.Append(value.Tag.ToString("00"));
            line.Append(") ");
            line.Append(" ");
            line.Append(new string(' ', (Depth + 1)));
            line.Append(" ");
            if (_explicitTag.HasValue)
            {
                line.Append("[" + _explicitTag.Value + "] ");
                _explicitTag = null;
            }
        }
    }
}