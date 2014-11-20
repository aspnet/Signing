namespace Microsoft.Framework.Asn1
{
    public enum Asn1Class
    {
        // NOTE: These enum values map exactly to the values defined in the ASN.1 BER encoding spec, do NOT change them!
        Universal = 0,
        Application = 1,
        ContextSpecific = 2,
        Private = 3
    }
}