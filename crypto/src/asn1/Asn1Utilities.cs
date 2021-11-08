using System;

namespace Org.BouncyCastle.Asn1
{
    public abstract class Asn1Utilities
    {
        public static string GetTagText(Asn1TaggedObject taggedObject)
        {
            return GetTagText(taggedObject.TagClass, taggedObject.TagNo);
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

        /*
         * Wrappers for Asn1TaggedObject.GetExplicitBaseObject
         */

        public static Asn1Encodable GetExplicitBaseObject(Asn1TaggedObject taggedObject, int tagClass, int tagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
            {
                string expected = GetTagText(tagClass, tagNo);
                string found = GetTagText(taggedObject);
                throw new InvalidOperationException("Expected " + expected + " tag but found " + found);
            }

            return taggedObject.GetExplicitBaseObject();
        }

        public static Asn1Encodable GetExplicitContextBaseObject(Asn1TaggedObject taggedObject, int tagNo)
        {
            return GetExplicitBaseObject(taggedObject, Asn1Tags.ContextSpecific, tagNo);
        }

        public static Asn1Encodable TryGetExplicitBaseObject(Asn1TaggedObject taggedObject, int tagClass, int tagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
                return null;

            return taggedObject.GetExplicitBaseObject();
        }

        public static Asn1Encodable TryGetExplicitContextBaseObject(Asn1TaggedObject taggedObject, int tagNo)
        {
            return TryGetExplicitBaseObject(taggedObject, Asn1Tags.ContextSpecific, tagNo);
        }


        /*
         * Wrappers for Asn1TaggedObject.GetExplicitBaseTagged
         */

        public static Asn1TaggedObject GetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
            {
                string expected = GetTagText(tagClass, tagNo);
                string found = GetTagText(taggedObject);
                throw new InvalidOperationException("Expected " + expected + " tag but found " + found);
            }

            return taggedObject.GetExplicitBaseTagged();
        }

        public static Asn1TaggedObject GetExplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo)
        {
            return GetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo);
        }

        public static Asn1TaggedObject TryGetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
                return null;

            return taggedObject.GetExplicitBaseTagged();
        }

        public static Asn1TaggedObject TryGetExplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo)
        {
            return TryGetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo);
        }
    }
}
