using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    // TODO[api] Make static
    public abstract class Asn1Utilities
    {
        internal static Asn1TaggedObject CheckTagClass(Asn1TaggedObject taggedObject, int tagClass)
        {
            if (!taggedObject.HasTagClass(tagClass))
            {
                string expected = GetTagClassText(tagClass);
                string found = GetTagClassText(taggedObject);
                throw new InvalidOperationException("Expected " + expected + " tag but found " + found);
            }
            return taggedObject;
        }

        internal static Asn1TaggedObjectParser CheckTagClass(Asn1TaggedObjectParser taggedObjectParser, int tagClass)
        {
            if (taggedObjectParser.TagClass != tagClass)
            {
                string expected = GetTagClassText(tagClass);
                string found = GetTagClassText(taggedObjectParser);
                throw new InvalidOperationException("Expected " + expected + " tag but found " + found);
            }
            return taggedObjectParser;
        }

        internal static Asn1TaggedObject CheckTag(Asn1TaggedObject taggedObject, int tagClass, int tagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
            {
                string expected = GetTagText(tagClass, tagNo);
                string found = GetTagText(taggedObject);
                throw new InvalidOperationException("Expected " + expected + " tag but found " + found);
            }
            return taggedObject;
        }

        internal static Asn1TaggedObjectParser CheckTag(Asn1TaggedObjectParser taggedObjectParser, int tagClass,
            int tagNo)
        {
            if (!taggedObjectParser.HasTag(tagClass, tagNo))
            {
                string expected = GetTagText(tagClass, tagNo);
                string found = GetTagText(taggedObjectParser);
                throw new InvalidOperationException("Expected " + expected + " tag but found " + found);
            }
            return taggedObjectParser;
        }


        internal static TChoice GetInstanceFromChoice<TChoice>(Asn1TaggedObject taggedObject, bool declaredExplicit,
            Func<object, TChoice> constructor)
            where TChoice : Asn1Encodable, IAsn1Choice
        {
            if (!declaredExplicit)
            {
                var message = string.Format(
                    "Implicit tagging cannot be used with untagged choice type {0} (X.680 30.6, 30.8).",
                    Platform.GetTypeName(typeof(TChoice)));

                throw new ArgumentException(message, nameof(declaredExplicit));
            }
            if (taggedObject == null)
                throw new ArgumentNullException(nameof(taggedObject));

            return constructor(taggedObject.GetExplicitBaseObject());
        }


        public static string GetTagClassText(int tagClass)
        {
            switch (tagClass)
            {
            case Asn1Tags.Application:
                return "APPLICATION";
            case Asn1Tags.ContextSpecific:
                return "CONTEXT";
            case Asn1Tags.Private:
                return "PRIVATE";
            default:
                return "UNIVERSAL";
            }
        }

        public static string GetTagClassText(Asn1TaggedObject taggedObject)
        {
            return GetTagClassText(taggedObject.TagClass);
        }

        public static string GetTagClassText(Asn1TaggedObjectParser taggedObjectParser)
        {
            return GetTagClassText(taggedObjectParser.TagClass);
        }

        internal static string GetTagText(Asn1Tag tag)
        {
            return GetTagText(tag.TagClass, tag.TagNo);
        }

        public static string GetTagText(Asn1TaggedObject taggedObject)
        {
            return GetTagText(taggedObject.TagClass, taggedObject.TagNo);
        }

        public static string GetTagText(Asn1TaggedObjectParser taggedObjectParser)
        {
            return GetTagText(taggedObjectParser.TagClass, taggedObjectParser.TagNo);
        }

        public static string GetTagText(int tagClass, int tagNo)
        {
            switch (tagClass)
            {
            case Asn1Tags.Application:
                return string.Format("[APPLICATION {0}]", tagNo);
            case Asn1Tags.ContextSpecific:
                return string.Format("[CONTEXT {0}]", tagNo);
            case Asn1Tags.Private:
                return string.Format("[PRIVATE {0}]", tagNo);
            default:
                return string.Format("[UNIVERSAL {0}]", tagNo);
            }
        }


        /*
         * Wrappers for Asn1TaggedObject.GetExplicitBaseObject
         */

        public static Asn1Encodable GetExplicitBaseObject(Asn1TaggedObject taggedObject, int tagClass, int tagNo)
        {
            return CheckTag(taggedObject, tagClass, tagNo).GetExplicitBaseObject();
        }

        public static Asn1Encodable GetExplicitContextBaseObject(Asn1TaggedObject taggedObject, int tagNo)
        {
            return GetExplicitBaseObject(taggedObject, Asn1Tags.ContextSpecific, tagNo);
        }

        [Obsolete("Will be removed")]
        public static Asn1Encodable TryGetExplicitBaseObject(Asn1TaggedObject taggedObject, int tagClass, int tagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
                return null;

            return taggedObject.GetExplicitBaseObject();
        }

        public static bool TryGetExplicitBaseObject(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            out Asn1Encodable baseObject)
        {
            bool result = taggedObject.HasTag(tagClass, tagNo);
            baseObject = result ? taggedObject.GetExplicitBaseObject() : null;
            return result;
        }

        [Obsolete("Will be removed")]
        public static Asn1Encodable TryGetExplicitContextBaseObject(Asn1TaggedObject taggedObject, int tagNo)
        {
            return TryGetExplicitBaseObject(taggedObject, Asn1Tags.ContextSpecific, tagNo);
        }

        public static bool TryGetExplicitContextBaseObject(Asn1TaggedObject taggedObject, int tagNo,
            out Asn1Encodable baseObject)
        {
            return TryGetExplicitBaseObject(taggedObject, Asn1Tags.ContextSpecific, tagNo, out baseObject);
        }


        /*
         * Wrappers for Asn1TaggedObject.GetExplicitBaseTagged
         */

        public static Asn1TaggedObject GetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass)
        {
            return CheckTagClass(taggedObject, tagClass).GetExplicitBaseTagged();
        }

        public static Asn1TaggedObject GetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo)
        {
            return CheckTag(taggedObject, tagClass, tagNo).GetExplicitBaseTagged();
        }

        public static Asn1TaggedObject GetExplicitContextBaseTagged(Asn1TaggedObject taggedObject)
        {
            return GetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific);
        }

        public static Asn1TaggedObject GetExplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo)
        {
            return GetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo);
        }

        [Obsolete("Will be removed")]
        public static Asn1TaggedObject TryGetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass)
        {
            if (!taggedObject.HasTagClass(tagClass))
                return null;

            return taggedObject.GetExplicitBaseTagged();
        }

        public static bool TryGetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass,
            out Asn1TaggedObject baseTagged)
        {
            bool result = taggedObject.HasTagClass(tagClass);
            baseTagged = result ? taggedObject.GetExplicitBaseTagged() : null;
            return result;
        }

        [Obsolete("Will be removed")]
        public static Asn1TaggedObject TryGetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
                return null;

            return taggedObject.GetExplicitBaseTagged();
        }

        public static bool TryGetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            out Asn1TaggedObject baseTagged)
        {
            bool result = taggedObject.HasTag(tagClass, tagNo);
            baseTagged = result ? taggedObject.GetExplicitBaseTagged() : null;
            return result;
        }

        [Obsolete("Will be removed")]
        public static Asn1TaggedObject TryGetExplicitContextBaseTagged(Asn1TaggedObject taggedObject)
        {
            return TryGetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific);
        }

        public static bool TryGetExplicitContextBaseTagged(Asn1TaggedObject taggedObject,
            out Asn1TaggedObject baseTagged)
        {
            return TryGetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, out baseTagged);
        }

        [Obsolete("Will be removed")]
        public static Asn1TaggedObject TryGetExplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo)
        {
            return TryGetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo);
        }

        public static bool TryGetExplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo,
            out Asn1TaggedObject baseTagged)
        {
            return TryGetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo, out baseTagged);
        }


        /*
         * Wrappers for Asn1TaggedObject.GetImplicitBaseTagged
         */

        public static Asn1TaggedObject GetImplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            int baseTagClass, int baseTagNo)
        {
            return CheckTag(taggedObject, tagClass, tagNo).GetImplicitBaseTagged(baseTagClass, baseTagNo);
        }

        public static Asn1TaggedObject GetImplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo,
            int baseTagClass, int baseTagNo)
        {
            return GetImplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo, baseTagClass, baseTagNo);
        }

        [Obsolete("Will be removed")]
        public static Asn1TaggedObject TryGetImplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            int baseTagClass, int baseTagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
                return null;

            return taggedObject.GetImplicitBaseTagged(baseTagClass, baseTagNo);
        }

        public static bool TryGetImplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            int baseTagClass, int baseTagNo, out Asn1TaggedObject baseTagged)
        {
            bool result = taggedObject.HasTag(tagClass, tagNo);
            baseTagged = result ? taggedObject.GetImplicitBaseTagged(baseTagClass, baseTagNo) : null;
            return result;
        }

        [Obsolete("Will be removed")]
        public static Asn1TaggedObject TryGetImplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo,
            int baseTagClass, int baseTagNo)
        {
            return TryGetImplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo, baseTagClass, baseTagNo);
        }

        public static bool TryGetImplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo, int baseTagClass,
            int baseTagNo, out Asn1TaggedObject baseTagged)
        {
            return TryGetImplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo, baseTagClass, baseTagNo,
                out baseTagged);
        }


        /*
         * Wrappers for Asn1TaggedObject.GetBaseUniversal
         */

        public static Asn1Object GetBaseUniversal(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            bool declaredExplicit, int baseTagNo)
        {
            return CheckTag(taggedObject, tagClass, tagNo).GetBaseUniversal(declaredExplicit, baseTagNo);
        }

        public static Asn1Object GetContextBaseUniversal(Asn1TaggedObject taggedObject, int tagNo,
            bool declaredExplicit, int baseTagNo)
        {
            return GetBaseUniversal(taggedObject, Asn1Tags.ContextSpecific, tagNo, declaredExplicit, baseTagNo);
        }

        [Obsolete("Will be removed")]
        public static Asn1Object TryGetBaseUniversal(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            bool declaredExplicit, int baseTagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
                return null;

            return taggedObject.GetBaseUniversal(declaredExplicit, baseTagNo);
        }

        public static bool TryGetBaseUniversal(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            bool declaredExplicit, int baseTagNo, out Asn1Object baseUniversal)
        {
            bool result = taggedObject.HasTag(tagClass, tagNo);
            baseUniversal = result ? taggedObject.GetBaseUniversal(declaredExplicit, baseTagNo) : null;
            return result;
        }

        [Obsolete("Will be removed")]
        public static Asn1Object TryGetContextBaseUniversal(Asn1TaggedObject taggedObject, int tagNo,
            bool declaredExplicit, int baseTagNo)
        {
            return TryGetBaseUniversal(taggedObject, Asn1Tags.ContextSpecific, tagNo, declaredExplicit, baseTagNo);
        }

        public static bool TryGetContextBaseUniversal(Asn1TaggedObject taggedObject, int tagNo, bool declaredExplicit,
            int baseTagNo, out Asn1Object baseUniversal)
        {
            return TryGetBaseUniversal(taggedObject, Asn1Tags.ContextSpecific, tagNo, declaredExplicit, baseTagNo,
                out baseUniversal);
        }


        /*
         * Wrappers for Asn1TaggedObjectParser.ParseExplicitBaseTagged
         */

        /// <exception cref="IOException"/>
        public static Asn1TaggedObjectParser ParseExplicitBaseTagged(Asn1TaggedObjectParser taggedObjectParser,
            int tagClass)
        {
            return CheckTagClass(taggedObjectParser, tagClass).ParseExplicitBaseTagged();
        }

        /// <exception cref="IOException"/>
        public static Asn1TaggedObjectParser ParseExplicitBaseTagged(Asn1TaggedObjectParser taggedObjectParser,
            int tagClass, int tagNo)
        {
            return CheckTag(taggedObjectParser, tagClass, tagNo).ParseExplicitBaseTagged();
        }

        /// <exception cref="IOException"/>
        public static Asn1TaggedObjectParser ParseExplicitContextBaseTagged(Asn1TaggedObjectParser taggedObjectParser)
        {
            return ParseExplicitBaseTagged(taggedObjectParser, Asn1Tags.ContextSpecific);
        }

        /// <exception cref="IOException"/>
        public static Asn1TaggedObjectParser ParseExplicitContextBaseTagged(Asn1TaggedObjectParser taggedObjectParser,
            int tagNo)
        {
            return ParseExplicitBaseTagged(taggedObjectParser, Asn1Tags.ContextSpecific, tagNo);
        }

        /// <exception cref="IOException"/>
        [Obsolete("Will be removed")]
        public static Asn1TaggedObjectParser TryParseExplicitBaseTagged(Asn1TaggedObjectParser taggedObjectParser,
            int tagClass)
        {
            if (taggedObjectParser.TagClass != tagClass)
                return null;

            return taggedObjectParser.ParseExplicitBaseTagged();
        }

        /// <exception cref="IOException"/>
        public static bool TryParseExplicitBaseTagged(Asn1TaggedObjectParser taggedObjectParser, int tagClass,
            out Asn1TaggedObjectParser baseTagged)
        {
            bool result = taggedObjectParser.TagClass == tagClass;
            baseTagged = result ? taggedObjectParser.ParseExplicitBaseTagged() : null;
            return result;
        }

        /// <exception cref="IOException"/>
        [Obsolete("Will be removed")]
        public static Asn1TaggedObjectParser TryParseExplicitBaseTagged(Asn1TaggedObjectParser taggedObjectParser,
            int tagClass, int tagNo)
        {
            if (!taggedObjectParser.HasTag(tagClass, tagNo))
                return null;

            return taggedObjectParser.ParseExplicitBaseTagged();
        }

        /// <exception cref="IOException"/>
        public static bool TryParseExplicitBaseTagged(Asn1TaggedObjectParser taggedObjectParser, int tagClass,
            int tagNo, out Asn1TaggedObjectParser baseTagged)
        {
            bool result = taggedObjectParser.HasTag(tagClass, tagNo);
            baseTagged = result ? taggedObjectParser.ParseExplicitBaseTagged() : null;
            return result;
        }

        /// <exception cref="IOException"/>
        [Obsolete("Will be removed")]
        public static Asn1TaggedObjectParser TryParseExplicitContextBaseTagged(
            Asn1TaggedObjectParser taggedObjectParser)
        {
            return TryParseExplicitBaseTagged(taggedObjectParser, Asn1Tags.ContextSpecific);
        }

        /// <exception cref="IOException"/>
        public static bool TryParseExplicitContextBaseTagged(Asn1TaggedObjectParser taggedObjectParser,
            out Asn1TaggedObjectParser baseTagged)
        {
            return TryParseExplicitBaseTagged(taggedObjectParser, Asn1Tags.ContextSpecific, out baseTagged);
        }

        /// <exception cref="IOException"/>
        [Obsolete("Will be removed")]
        public static Asn1TaggedObjectParser TryParseExplicitContextBaseTagged(
            Asn1TaggedObjectParser taggedObjectParser, int tagNo)
        {
            return TryParseExplicitBaseTagged(taggedObjectParser, Asn1Tags.ContextSpecific, tagNo);
        }

        /// <exception cref="IOException"/>
        public static bool TryParseExplicitContextBaseTagged(Asn1TaggedObjectParser taggedObjectParser, int tagNo,
            out Asn1TaggedObjectParser baseTagged)
        {
            return TryParseExplicitBaseTagged(taggedObjectParser, Asn1Tags.ContextSpecific, tagNo, out baseTagged);
        }


        /*
         * Wrappers for Asn1TaggedObjectParser.ParseImplicitBaseTagged
         */

        /// <exception cref="IOException"/>
        public static Asn1TaggedObjectParser ParseImplicitBaseTagged(Asn1TaggedObjectParser taggedObjectParser,
            int tagClass, int tagNo, int baseTagClass, int baseTagNo)
        {
            return CheckTag(taggedObjectParser, tagClass, tagNo).ParseImplicitBaseTagged(baseTagClass, baseTagNo);
        }

        /// <exception cref="IOException"/>
        public static Asn1TaggedObjectParser ParseImplicitContextBaseTagged(Asn1TaggedObjectParser taggedObjectParser,
            int tagNo, int baseTagClass, int baseTagNo)
        {
            return ParseImplicitBaseTagged(taggedObjectParser, Asn1Tags.ContextSpecific, tagNo, baseTagClass,
                baseTagNo);
        }

        /// <exception cref="IOException"/>
        [Obsolete("Will be removed")]
        public static Asn1TaggedObjectParser TryParseImplicitBaseTagged(Asn1TaggedObjectParser taggedObjectParser,
            int tagClass, int tagNo, int baseTagClass, int baseTagNo)
        {
            if (!taggedObjectParser.HasTag(tagClass, tagNo))
                return null;

            return taggedObjectParser.ParseImplicitBaseTagged(baseTagClass, baseTagNo);
        }

        /// <exception cref="IOException"/>
        public static bool TryParseImplicitBaseTagged(Asn1TaggedObjectParser taggedObjectParser, int tagClass,
            int tagNo, int baseTagClass, int baseTagNo, out Asn1TaggedObjectParser baseTagged)
        {
            bool result = taggedObjectParser.HasTag(tagClass, tagNo);
            baseTagged = result ? taggedObjectParser.ParseImplicitBaseTagged(baseTagClass, baseTagNo) : null;
            return result;
        }

        /// <exception cref="IOException"/>
        [Obsolete("Will be removed")]
        public static Asn1TaggedObjectParser TryParseImplicitContextBaseTagged(
            Asn1TaggedObjectParser taggedObjectParser, int tagNo, int baseTagClass, int baseTagNo)
        {
            return TryParseImplicitBaseTagged(taggedObjectParser, Asn1Tags.ContextSpecific, tagNo, baseTagClass,
                baseTagNo);
        }

        /// <exception cref="IOException"/>
        public static bool TryParseImplicitContextBaseTagged(Asn1TaggedObjectParser taggedObjectParser, int tagNo,
            int baseTagClass, int baseTagNo, out Asn1TaggedObjectParser baseTagged)
        {
            return TryParseImplicitBaseTagged(taggedObjectParser, Asn1Tags.ContextSpecific, tagNo, baseTagClass,
                baseTagNo, out baseTagged);
        }


        /*
         * Wrappers for Asn1TaggedObjectParser.ParseBaseUniversal
         */

        /// <exception cref="IOException"/>
        public static IAsn1Convertible ParseBaseUniversal(Asn1TaggedObjectParser taggedObjectParser, int tagClass,
            int tagNo, bool declaredExplicit, int baseTagNo)
        {
            return CheckTag(taggedObjectParser, tagClass, tagNo).ParseBaseUniversal(declaredExplicit, baseTagNo);
        }

        /// <exception cref="IOException"/>
        public static IAsn1Convertible ParseContextBaseUniversal(Asn1TaggedObjectParser taggedObjectParser, int tagNo,
            bool declaredExplicit, int baseTagNo)
        {
            return ParseBaseUniversal(taggedObjectParser, Asn1Tags.ContextSpecific, tagNo, declaredExplicit, baseTagNo);
        }

        /// <exception cref="IOException"/>
        [Obsolete("Will be removed")]
        public static IAsn1Convertible TryParseBaseUniversal(Asn1TaggedObjectParser taggedObjectParser, int tagClass,
            int tagNo, bool declaredExplicit, int baseTagNo)
        {
            if (!taggedObjectParser.HasTag(tagClass, tagNo))
                return null;

            return taggedObjectParser.ParseBaseUniversal(declaredExplicit, baseTagNo);
        }

        /// <exception cref="IOException"/>
        public static bool TryParseBaseUniversal(Asn1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo,
            bool declaredExplicit, int baseTagNo, out IAsn1Convertible baseUniversal)
        {
            bool result = taggedObjectParser.HasTag(tagClass, tagNo);
            baseUniversal = result ? taggedObjectParser.ParseBaseUniversal(declaredExplicit, baseTagNo) : null;
            return result;
        }

        /// <exception cref="IOException"/>
        [Obsolete("Will be removed")]
        public static IAsn1Convertible TryParseContextBaseUniversal(Asn1TaggedObjectParser taggedObjectParser,
            int tagNo, bool declaredExplicit, int baseTagNo)
        {
            return TryParseBaseUniversal(taggedObjectParser, Asn1Tags.ContextSpecific, tagNo, declaredExplicit,
                baseTagNo);
        }

        /// <exception cref="IOException"/>
        public static bool TryParseContextBaseUniversal(Asn1TaggedObjectParser taggedObjectParser, int tagNo,
            bool declaredExplicit, int baseTagNo, out IAsn1Convertible baseUniversal)
        {
            return TryParseBaseUniversal(taggedObjectParser, Asn1Tags.ContextSpecific, tagNo, declaredExplicit,
                baseTagNo, out baseUniversal);
        }


        /*
         * Wrappers for Asn1TaggedObjectParser.ParseExplicitBaseObject
         */

        /// <exception cref="IOException"/>
        public static IAsn1Convertible ParseExplicitBaseObject(Asn1TaggedObjectParser taggedObjectParser, int tagClass,
            int tagNo)
        {
            return CheckTag(taggedObjectParser, tagClass, tagNo).ParseExplicitBaseObject();
        }

        /// <exception cref="IOException"/>
        public static IAsn1Convertible ParseExplicitContextBaseObject(Asn1TaggedObjectParser taggedObjectParser,
            int tagNo)
        {
            return ParseExplicitBaseObject(taggedObjectParser, Asn1Tags.ContextSpecific, tagNo);
        }

        /// <exception cref="IOException"/>
        [Obsolete("Will be removed")]
        public static IAsn1Convertible TryParseExplicitBaseObject(Asn1TaggedObjectParser taggedObjectParser,
            int tagClass, int tagNo)
        {
            if (!taggedObjectParser.HasTag(tagClass, tagNo))
                return null;

            return taggedObjectParser.ParseExplicitBaseObject();
        }

        /// <exception cref="IOException"/>
        public static bool TryParseExplicitBaseObject(Asn1TaggedObjectParser taggedObjectParser, int tagClass,
            int tagNo, out IAsn1Convertible baseObject)
        {
            bool result = taggedObjectParser.HasTag(tagClass, tagNo);
            baseObject = result ? taggedObjectParser.ParseExplicitBaseObject() : null;
            return result;
        }

        /// <exception cref="IOException"/>
        [Obsolete("Will be removed")]
        public static IAsn1Convertible TryParseExplicitContextBaseObject(Asn1TaggedObjectParser taggedObjectParser,
            int tagNo)
        {
            return TryParseExplicitBaseObject(taggedObjectParser, Asn1Tags.ContextSpecific, tagNo);
        }

        /// <exception cref="IOException"/>
        public static bool TryParseExplicitContextBaseObject(Asn1TaggedObjectParser taggedObjectParser, int tagNo,
            out IAsn1Convertible baseObject)
        {
            return TryParseExplicitBaseObject(taggedObjectParser, Asn1Tags.ContextSpecific, tagNo, out baseObject);
        }
    }
}
