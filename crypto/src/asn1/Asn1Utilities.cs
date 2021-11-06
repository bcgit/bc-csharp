using System;

namespace Org.BouncyCastle.Asn1
{
    public abstract class Asn1Utilities
    {
        public static string GetTagText(Asn1TaggedObject taggedObject)
        {
            // TODO[asn1] Implement and use taggedObject.TagClass
            return GetTagText(Asn1Tags.ContextSpecific, taggedObject.TagNo);
        }

        public static string GetTagText(int tagClass, int tagNo)
        {
            switch (tagClass)
            {
            case Asn1Tags.Application:
                return "[APPLICATION " + tagNo + "]";
            case Asn1Tags.ContextSpecific:
                return "[CONTEXT " + tagNo + "]";
            case Asn1Tags.Private:
                return "[PRIVATE " + tagNo + "]";
            default:
                return "[UNIVERSAL " + tagNo + "]";
            }
        }
    }
}
