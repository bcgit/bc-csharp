using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Utility methods for working with ASN.1 objects.</summary>
    // TODO[api] Make static
    public abstract class Asn1Utilities
    {
        /// <summary>Check that a tagged object has the context-specific tag class and the given tag number.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <returns>The tagged object, if the tag matches.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObject CheckContextTag(Asn1TaggedObject taggedObject, int tagNo)
        {
            return CheckTag(taggedObject, Asn1Tags.ContextSpecific, tagNo);
        }

        /// <summary>Check that a tagged object has the context-specific tag class and the given tag number.</summary>
        /// <param name="taggedObjectParser">The tagged object parser.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <returns>The tagged object, if the tag matches.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObjectParser CheckContextTag(Asn1TaggedObjectParser taggedObjectParser, int tagNo)
        {
            return CheckTag(taggedObjectParser, Asn1Tags.ContextSpecific, tagNo);
        }

        /// <summary>Check that a tagged object has the context-specific tag class.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <returns>The tagged object, if the tag class matches.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObject CheckContextTagClass(Asn1TaggedObject taggedObject)
        {
            return CheckTagClass(taggedObject, Asn1Tags.ContextSpecific);
        }

        /// <summary>Check that a tagged object has the context-specific tag class.</summary>
        /// <param name="taggedObjectParser">The tagged object parser.</param>
        /// <returns>The tagged object, if the tag class matches.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObjectParser CheckContextTagClass(Asn1TaggedObjectParser taggedObjectParser)
        {
            return CheckTagClass(taggedObjectParser, Asn1Tags.ContextSpecific);
        }

        /// <summary>Check that a tagged object has the given tag class and tag number.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <returns>The tagged object, if the tag matches.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObject CheckTag(Asn1TaggedObject taggedObject, int tagClass, int tagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
            {
                string expected = GetTagText(tagClass, tagNo);
                string found = GetTagText(taggedObject);
                throw new InvalidOperationException("Expected " + expected + " tag but found " + found);
            }
            return taggedObject;
        }

        /// <summary>Check that a tagged object has the given tag class and tag number.</summary>
        /// <param name="taggedObjectParser">The tagged object parser.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <returns>The tagged object, if the tag matches.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObjectParser CheckTag(Asn1TaggedObjectParser taggedObjectParser, int tagClass,
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

        /// <summary>Check that a tagged object has the given tag class.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <returns>The tagged object, if the tag class matches.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObject CheckTagClass(Asn1TaggedObject taggedObject, int tagClass)
        {
            if (!taggedObject.HasTagClass(tagClass))
            {
                string expected = GetTagClassText(tagClass);
                string found = GetTagClassText(taggedObject);
                throw new InvalidOperationException("Expected " + expected + " tag but found " + found);
            }
            return taggedObject;
        }

        /// <summary>Check that a tagged object has the given tag class.</summary>
        /// <param name="taggedObjectParser">The tagged object parser.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <returns>The tagged object, if the tag class matches.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObjectParser CheckTagClass(Asn1TaggedObjectParser taggedObjectParser, int tagClass)
        {
            if (taggedObjectParser.TagClass != tagClass)
            {
                string expected = GetTagClassText(tagClass);
                string found = GetTagClassText(taggedObjectParser);
                throw new InvalidOperationException("Expected " + expected + " tag but found " + found);
            }
            return taggedObjectParser;
        }

        /// <summary>Get an instance of a CHOICE type from an object.</summary>
        /// <param name="obj">An instance of the type, an object from which one can be constructed, or null.</param>
        /// <param name="optionalConstructor">
        /// A function that constructs the choice from an ASN.1 element, returning null if the element is not valid.
        /// </param>
        /// <returns>The instance, or null if <paramref name="obj"/> is null.</returns>
        /// <exception cref="ArgumentException">The object is not valid.</exception>
        public static TChoice GetInstanceChoice<TChoice>(object obj, Func<Asn1Encodable, TChoice> optionalConstructor)
            where TChoice : Asn1Encodable, IAsn1Choice
        {
            if (obj == null)
                return null;

            if (obj is byte[] bytes)
            {
                try
                {
                    obj = Asn1Object.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    var choiceName = Platform.GetTypeName(typeof(TChoice));
                    throw new ArgumentException($"failed to construct {choiceName} from byte[]", nameof(obj), e);
                }
            }

            if (obj is Asn1Encodable element)
            {
                var result = optionalConstructor(element);
                if (result != null)
                    return result;
            }

            throw new ArgumentException("Invalid object: " + Platform.GetTypeName(obj), nameof(obj));
        }

        /// <summary>
        /// Get an instance of an untagged CHOICE type from a context-specific tagged object that wraps it explicitly.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">
        /// true if the tagging was declared as explicit, which is required for a CHOICE type.
        /// </param>
        /// <param name="constructor">A function that constructs the choice from an ASN.1 element.</param>
        /// <returns>The instance.</returns>
        /// <exception cref="ArgumentException">The tagging was not declared as explicit.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="taggedObject"/> is null.</exception>
        public static TChoice GetInstanceChoice<TChoice>(Asn1TaggedObject taggedObject, bool declaredExplicit,
            Func<Asn1Encodable, TChoice> constructor)
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

            return constructor(GetExplicitContextBaseObject(taggedObject));
        }

        /// <summary>Get an instance of an untagged CHOICE type from a tagged object that wraps it explicitly.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">
        /// true if the tagging was declared as explicit, which is required for a CHOICE type.
        /// </param>
        /// <param name="constructor">A function that constructs the choice from an ASN.1 element.</param>
        /// <returns>The instance.</returns>
        /// <exception cref="ArgumentException">The tagging was not declared as explicit.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="taggedObject"/> is null.</exception>
        public static TChoice GetTaggedChoice<TChoice>(Asn1TaggedObject taggedObject, bool declaredExplicit,
            Func<Asn1Encodable, TChoice> constructor)
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


        /*
         * Tag text methods
         */

        internal static string GetTagClassText(Asn1Tag tag)
        {
            return GetTagClassText(tag.TagClass);
        }

        /// <summary>Get a textual description of the tag class of a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <returns>The description.</returns>
        public static string GetTagClassText(Asn1TaggedObject taggedObject)
        {
            return GetTagClassText(taggedObject.TagClass);
        }

        /// <summary>Get a textual description of the tag class of a tagged object.</summary>
        /// <param name="taggedObjectParser">The tagged object parser.</param>
        /// <returns>The description.</returns>
        public static string GetTagClassText(Asn1TaggedObjectParser taggedObjectParser)
        {
            return GetTagClassText(taggedObjectParser.TagClass);
        }

        /// <summary>Get a textual description of a tag class.</summary>
        /// <param name="tagClass">The tag class.</param>
        /// <returns>The description.</returns>
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
            case Asn1Tags.Universal:
                return "UNIVERSAL";
            default:
                return string.Format("UNKNOWN({0})", tagClass);
            }
        }

        internal static string GetTagText(Asn1Tag tag)
        {
            return GetTagText(tag.TagClass, tag.TagNo);
        }

        /// <summary>Get a textual description of the tag of a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <returns>The description.</returns>
        public static string GetTagText(Asn1TaggedObject taggedObject)
        {
            return GetTagText(taggedObject.TagClass, taggedObject.TagNo);
        }

        /// <summary>Get a textual description of the tag of a tagged object.</summary>
        /// <param name="taggedObjectParser">The tagged object parser.</param>
        /// <returns>The description.</returns>
        public static string GetTagText(Asn1TaggedObjectParser taggedObjectParser)
        {
            return GetTagText(taggedObjectParser.TagClass, taggedObjectParser.TagNo);
        }

        /// <summary>Get a textual description of a tag.</summary>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <returns>The description.</returns>
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
            case Asn1Tags.Universal:
                return string.Format("[UNIVERSAL {0}]", tagNo);
            default:
                return string.Format("[UNKNOWN({0}) {1}]", tagClass, tagNo);
            }
        }


        /*
         * Wrappers for Asn1TaggedObject.GetExplicitBaseObject
         */

        /// <summary>Check the tag of an explicitly tagged object and return its base object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <returns>The base object.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1Encodable GetExplicitBaseObject(Asn1TaggedObject taggedObject, int tagClass) =>
            CheckTagClass(taggedObject, tagClass).GetExplicitBaseObject();

        /// <summary>Check the tag of an explicitly tagged object and return its base object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <returns>The base object.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1Encodable GetExplicitBaseObject(Asn1TaggedObject taggedObject, int tagClass, int tagNo) =>
            CheckTag(taggedObject, tagClass, tagNo).GetExplicitBaseObject();

        /// <summary>Check the tag of an explicitly tagged object and return its base object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <returns>The base object.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1Encodable GetExplicitContextBaseObject(Asn1TaggedObject taggedObject) =>
            GetExplicitBaseObject(taggedObject, Asn1Tags.ContextSpecific);

        /// <summary>Check the tag of an explicitly tagged object and return its base object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <returns>The base object.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1Encodable GetExplicitContextBaseObject(Asn1TaggedObject taggedObject, int tagNo) =>
            GetExplicitBaseObject(taggedObject, Asn1Tags.ContextSpecific, tagNo);

        /// <summary>Get the base object of an explicitly tagged object if it has the expected tag.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <returns>The base object, or null if the tag does not match.</returns>
        [Obsolete("Will be removed")]
        public static Asn1Encodable TryGetExplicitBaseObject(Asn1TaggedObject taggedObject, int tagClass, int tagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
                return null;

            return taggedObject.GetExplicitBaseObject();
        }

        /// <summary>Try to get the base object of an explicitly tagged object with the expected tag.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="baseObject">On success, the base object.</param>
        /// <returns>true if the tag matched and the base object was obtained, false otherwise.</returns>
        public static bool TryGetExplicitBaseObject(Asn1TaggedObject taggedObject, int tagClass,
            out Asn1Encodable baseObject)
        {
            bool result = taggedObject.HasTagClass(tagClass);
            baseObject = result ? taggedObject.GetExplicitBaseObject() : null;
            return result;
        }

        /// <summary>Try to get the base object of an explicitly tagged object with the expected tag.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="baseObject">On success, the base object.</param>
        /// <returns>true if the tag matched and the base object was obtained, false otherwise.</returns>
        public static bool TryGetExplicitBaseObject(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            out Asn1Encodable baseObject)
        {
            bool result = taggedObject.HasTag(tagClass, tagNo);
            baseObject = result ? taggedObject.GetExplicitBaseObject() : null;
            return result;
        }

        /// <summary>Get the base object of an explicitly tagged object if it has the expected tag.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <returns>The base object, or null if the tag does not match.</returns>
        [Obsolete("Will be removed")]
        public static Asn1Encodable TryGetExplicitContextBaseObject(Asn1TaggedObject taggedObject, int tagNo)
        {
            return TryGetExplicitBaseObject(taggedObject, Asn1Tags.ContextSpecific, tagNo);
        }

        /// <summary>Try to get the base object of an explicitly tagged object with the expected tag.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="baseObject">On success, the base object.</param>
        /// <returns>true if the tag matched and the base object was obtained, false otherwise.</returns>
        public static bool TryGetExplicitContextBaseObject(Asn1TaggedObject taggedObject, out Asn1Encodable baseObject)
        {
            return TryGetExplicitBaseObject(taggedObject, Asn1Tags.ContextSpecific, out baseObject);
        }

        /// <summary>Try to get the base object of an explicitly tagged object with the expected tag.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="baseObject">On success, the base object.</param>
        /// <returns>true if the tag matched and the base object was obtained, false otherwise.</returns>
        public static bool TryGetExplicitContextBaseObject(Asn1TaggedObject taggedObject, int tagNo,
            out Asn1Encodable baseObject)
        {
            return TryGetExplicitBaseObject(taggedObject, Asn1Tags.ContextSpecific, tagNo, out baseObject);
        }


        /*
         * Wrappers for Asn1TaggedObject.GetOptional
         */

        /// <summary>Get a value from an element, if the element is a tagged object with the expected tag.</summary>
        /// <param name="element">The element.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="state">The state passed to the constructor.</param>
        /// <param name="constructor">A function that constructs the result from the tagged object.</param>
        /// <returns>The result, or null if the element is not a matching tagged object.</returns>
        public static TResult GetOptionalContextTagged<TState, TResult>(Asn1Encodable element, int tagNo, TState state,
            Func<Asn1TaggedObject, TState, TResult> constructor)
            where TResult : class
        {
            return GetOptionalTagged(element, Asn1Tags.ContextSpecific, tagNo, state, constructor);
        }

        /// <summary>Get a value from an element, if the element is a tagged object with the expected tag.</summary>
        /// <param name="element">The element.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="state">The state passed to the constructor.</param>
        /// <param name="constructor">A function that constructs the result from the tagged object.</param>
        /// <returns>The result, or null if the element is not a matching tagged object.</returns>
        public static TResult GetOptionalTagged<TState, TResult>(Asn1Encodable element, int tagClass, int tagNo,
            TState state, Func<Asn1TaggedObject, TState, TResult> constructor)
            where TResult : class
        {
            var taggedObject = Asn1TaggedObject.GetOptional(element, tagClass, tagNo);

            return taggedObject == null ? null : constructor(taggedObject, state);
        }

        /// <summary>
        /// Try to get a value from an element, if the element is a tagged object with the expected tag.
        /// </summary>
        /// <param name="element">The element.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="state">The state passed to the constructor.</param>
        /// <param name="result">On success, the result.</param>
        /// <param name="constructor">A function that constructs the result from the tagged object.</param>
        /// <returns>true if the element is a matching tagged object, false otherwise.</returns>
        public static bool TryGetOptionalContextTagged<TState, TResult>(Asn1Encodable element, int tagNo, TState state,
            out TResult result, Func<Asn1TaggedObject, TState, TResult> constructor)
        {
            return TryGetOptionalTagged(element, Asn1Tags.ContextSpecific, tagNo, state, out result, constructor);
        }

        /// <summary>
        /// Try to get a value from an element, if the element is a tagged object with the expected tag.
        /// </summary>
        /// <param name="element">The element.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="state">The state passed to the constructor.</param>
        /// <param name="result">On success, the result.</param>
        /// <param name="constructor">A function that constructs the result from the tagged object.</param>
        /// <returns>true if the element is a matching tagged object, false otherwise.</returns>
        public static bool TryGetOptionalTagged<TState, TResult>(Asn1Encodable element, int tagClass, int tagNo,
            TState state, out TResult result, Func<Asn1TaggedObject, TState, TResult> constructor)
        {
            var taggedObject = Asn1TaggedObject.GetOptional(element, tagClass, tagNo);
            if (taggedObject != null)
            {
                result = constructor(taggedObject, state);
                return true;
            }

            result = default;
            return false;
        }


        /*
         * Wrappers for Asn1TaggedObject.GetExplicitBaseTagged
         */

        /// <summary>
        /// Check the tag of an explicitly tagged object and return its base object as a tagged object.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <returns>The base tagged object.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObject GetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass)
        {
            return CheckTagClass(taggedObject, tagClass).GetExplicitBaseTagged();
        }

        /// <summary>
        /// Check the tag of an explicitly tagged object and return its base object as a tagged object.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <returns>The base tagged object.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObject GetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo)
        {
            return CheckTag(taggedObject, tagClass, tagNo).GetExplicitBaseTagged();
        }

        /// <summary>
        /// Check the tag of an explicitly tagged object and return its base object as a tagged object.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <returns>The base tagged object.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObject GetExplicitContextBaseTagged(Asn1TaggedObject taggedObject)
        {
            return GetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific);
        }

        /// <summary>
        /// Check the tag of an explicitly tagged object and return its base object as a tagged object.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <returns>The base tagged object.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObject GetExplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo)
        {
            return GetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo);
        }

        /// <summary>
        /// Get the base object of an explicitly tagged object, as a tagged object, if it has the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <returns>The base tagged object, or null if the tag does not match.</returns>
        [Obsolete("Will be removed")]
        public static Asn1TaggedObject TryGetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass)
        {
            if (!taggedObject.HasTagClass(tagClass))
                return null;

            return taggedObject.GetExplicitBaseTagged();
        }

        /// <summary>
        /// Try to get the base object of an explicitly tagged object, as a tagged object, if it has the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="baseTagged">On success, the base tagged object.</param>
        /// <returns>true if the tag matched and the base object was obtained, false otherwise.</returns>
        public static bool TryGetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass,
            out Asn1TaggedObject baseTagged)
        {
            bool result = taggedObject.HasTagClass(tagClass);
            baseTagged = result ? taggedObject.GetExplicitBaseTagged() : null;
            return result;
        }

        /// <summary>
        /// Get the base object of an explicitly tagged object, as a tagged object, if it has the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <returns>The base tagged object, or null if the tag does not match.</returns>
        [Obsolete("Will be removed")]
        public static Asn1TaggedObject TryGetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
                return null;

            return taggedObject.GetExplicitBaseTagged();
        }

        /// <summary>
        /// Try to get the base object of an explicitly tagged object, as a tagged object, if it has the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="baseTagged">On success, the base tagged object.</param>
        /// <returns>true if the tag matched and the base object was obtained, false otherwise.</returns>
        public static bool TryGetExplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            out Asn1TaggedObject baseTagged)
        {
            bool result = taggedObject.HasTag(tagClass, tagNo);
            baseTagged = result ? taggedObject.GetExplicitBaseTagged() : null;
            return result;
        }

        /// <summary>
        /// Get the base object of an explicitly tagged object, as a tagged object, if it has the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <returns>The base tagged object, or null if the tag does not match.</returns>
        [Obsolete("Will be removed")]
        public static Asn1TaggedObject TryGetExplicitContextBaseTagged(Asn1TaggedObject taggedObject)
        {
            return TryGetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific);
        }

        /// <summary>
        /// Try to get the base object of an explicitly tagged object, as a tagged object, if it has the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="baseTagged">On success, the base tagged object.</param>
        /// <returns>true if the tag matched and the base object was obtained, false otherwise.</returns>
        public static bool TryGetExplicitContextBaseTagged(Asn1TaggedObject taggedObject,
            out Asn1TaggedObject baseTagged)
        {
            return TryGetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, out baseTagged);
        }

        /// <summary>
        /// Get the base object of an explicitly tagged object, as a tagged object, if it has the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <returns>The base tagged object, or null if the tag does not match.</returns>
        [Obsolete("Will be removed")]
        public static Asn1TaggedObject TryGetExplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo)
        {
            return TryGetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo);
        }

        /// <summary>
        /// Try to get the base object of an explicitly tagged object, as a tagged object, if it has the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="baseTagged">On success, the base tagged object.</param>
        /// <returns>true if the tag matched and the base object was obtained, false otherwise.</returns>
        public static bool TryGetExplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo,
            out Asn1TaggedObject baseTagged)
        {
            return TryGetExplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo, out baseTagged);
        }


        /*
         * Wrappers for Asn1TaggedObject.GetImplicitBaseTagged
         */

        /// <summary>
        /// Check the tag of an implicitly tagged object and return its base object as a tagged object with the given
        /// base tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="baseTagClass">The tag class of the base object.</param>
        /// <param name="baseTagNo">The tag number of the base object.</param>
        /// <returns>The base tagged object.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObject GetImplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            int baseTagClass, int baseTagNo)
        {
            return CheckTag(taggedObject, tagClass, tagNo).GetImplicitBaseTagged(baseTagClass, baseTagNo);
        }

        /// <summary>
        /// Check the tag of an implicitly tagged object and return its base object as a tagged object with the given
        /// base tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="baseTagClass">The tag class of the base object.</param>
        /// <param name="baseTagNo">The tag number of the base object.</param>
        /// <returns>The base tagged object.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1TaggedObject GetImplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo,
            int baseTagClass, int baseTagNo)
        {
            return GetImplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo, baseTagClass, baseTagNo);
        }

        /// <summary>
        /// Get the base object of an implicitly tagged object, as a tagged object with the given base tag, if it has
        /// the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="baseTagClass">The tag class of the base object.</param>
        /// <param name="baseTagNo">The tag number of the base object.</param>
        /// <returns>The base tagged object, or null if the tag does not match.</returns>
        [Obsolete("Will be removed")]
        public static Asn1TaggedObject TryGetImplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            int baseTagClass, int baseTagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
                return null;

            return taggedObject.GetImplicitBaseTagged(baseTagClass, baseTagNo);
        }

        /// <summary>
        /// Try to get the base object of an implicitly tagged object, as a tagged object with the given base tag, if it
        /// has the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="baseTagClass">The tag class of the base object.</param>
        /// <param name="baseTagNo">The tag number of the base object.</param>
        /// <param name="baseTagged">On success, the base tagged object.</param>
        /// <returns>true if the tag matched and the base object was obtained, false otherwise.</returns>
        public static bool TryGetImplicitBaseTagged(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            int baseTagClass, int baseTagNo, out Asn1TaggedObject baseTagged)
        {
            bool result = taggedObject.HasTag(tagClass, tagNo);
            baseTagged = result ? taggedObject.GetImplicitBaseTagged(baseTagClass, baseTagNo) : null;
            return result;
        }

        /// <summary>
        /// Get the base object of an implicitly tagged object, as a tagged object with the given base tag, if it has
        /// the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="baseTagClass">The tag class of the base object.</param>
        /// <param name="baseTagNo">The tag number of the base object.</param>
        /// <returns>The base tagged object, or null if the tag does not match.</returns>
        [Obsolete("Will be removed")]
        public static Asn1TaggedObject TryGetImplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo,
            int baseTagClass, int baseTagNo)
        {
            return TryGetImplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo, baseTagClass, baseTagNo);
        }

        /// <summary>
        /// Try to get the base object of an implicitly tagged object, as a tagged object with the given base tag, if it
        /// has the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="baseTagClass">The tag class of the base object.</param>
        /// <param name="baseTagNo">The tag number of the base object.</param>
        /// <param name="baseTagged">On success, the base tagged object.</param>
        /// <returns>true if the tag matched and the base object was obtained, false otherwise.</returns>
        public static bool TryGetImplicitContextBaseTagged(Asn1TaggedObject taggedObject, int tagNo, int baseTagClass,
            int baseTagNo, out Asn1TaggedObject baseTagged)
        {
            return TryGetImplicitBaseTagged(taggedObject, Asn1Tags.ContextSpecific, tagNo, baseTagClass, baseTagNo,
                out baseTagged);
        }


        /*
         * Wrappers for Asn1TaggedObject.GetBaseUniversal
         */

        /// <summary>Check the tag of a tagged object and return its base object as a universal object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="declaredExplicit">true if the tagging was declared as explicit, false if implicit.</param>
        /// <param name="baseTagNo">The universal tag number of the base object.</param>
        /// <returns>The base object.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1Object GetBaseUniversal(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            bool declaredExplicit, int baseTagNo)
        {
            return CheckTag(taggedObject, tagClass, tagNo).GetBaseUniversal(declaredExplicit, baseTagNo);
        }

        /// <summary>Check the tag of a tagged object and return its base object as a universal object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="declaredExplicit">true if the tagging was declared as explicit, false if implicit.</param>
        /// <param name="baseTagNo">The universal tag number of the base object.</param>
        /// <returns>The base object.</returns>
        /// <exception cref="InvalidOperationException">The tag does not match.</exception>
        public static Asn1Object GetContextBaseUniversal(Asn1TaggedObject taggedObject, int tagNo,
            bool declaredExplicit, int baseTagNo)
        {
            return GetBaseUniversal(taggedObject, Asn1Tags.ContextSpecific, tagNo, declaredExplicit, baseTagNo);
        }

        /// <summary>Get the base object of a tagged object as a universal object, if it has the expected tag.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="declaredExplicit">true if the tagging was declared as explicit, false if implicit.</param>
        /// <param name="baseTagNo">The universal tag number of the base object.</param>
        /// <returns>The base object, or null if the tag does not match.</returns>
        [Obsolete("Will be removed")]
        public static Asn1Object TryGetBaseUniversal(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            bool declaredExplicit, int baseTagNo)
        {
            if (!taggedObject.HasTag(tagClass, tagNo))
                return null;

            return taggedObject.GetBaseUniversal(declaredExplicit, baseTagNo);
        }

        /// <summary>
        /// Try to get the base object of a tagged object as a universal object, if it has the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="declaredExplicit">true if the tagging was declared as explicit, false if implicit.</param>
        /// <param name="baseTagNo">The universal tag number of the base object.</param>
        /// <param name="baseUniversal">On success, the base object.</param>
        /// <returns>true if the tag matched and the base object was obtained, false otherwise.</returns>
        public static bool TryGetBaseUniversal(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            bool declaredExplicit, int baseTagNo, out Asn1Object baseUniversal)
        {
            bool result = taggedObject.HasTag(tagClass, tagNo);
            baseUniversal = result ? taggedObject.GetBaseUniversal(declaredExplicit, baseTagNo) : null;
            return result;
        }

        /// <summary>Get the base object of a tagged object as a universal object, if it has the expected tag.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="declaredExplicit">true if the tagging was declared as explicit, false if implicit.</param>
        /// <param name="baseTagNo">The universal tag number of the base object.</param>
        /// <returns>The base object, or null if the tag does not match.</returns>
        [Obsolete("Will be removed")]
        public static Asn1Object TryGetContextBaseUniversal(Asn1TaggedObject taggedObject, int tagNo,
            bool declaredExplicit, int baseTagNo)
        {
            return TryGetBaseUniversal(taggedObject, Asn1Tags.ContextSpecific, tagNo, declaredExplicit, baseTagNo);
        }

        /// <summary>
        /// Try to get the base object of a tagged object as a universal object, if it has the expected tag.
        /// </summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="declaredExplicit">true if the tagging was declared as explicit, false if implicit.</param>
        /// <param name="baseTagNo">The universal tag number of the base object.</param>
        /// <param name="baseUniversal">On success, the base object.</param>
        /// <returns>true if the tag matched and the base object was obtained, false otherwise.</returns>
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


        #region Sequence cursor

        /// <summary>Read the next element of a sequence, advancing the position.</summary>
        /// <param name="sequence">The sequence.</param>
        /// <param name="sequencePosition">The position in the sequence; advanced if an element is consumed.</param>
        /// <param name="constructor">A function that constructs the result from the element.</param>
        /// <returns>The result.</returns>
        /// <exception cref="InvalidOperationException">There are no more elements in the sequence.</exception>
        public static TResult Read<TResult>(Asn1Sequence sequence, ref int sequencePosition,
            Func<Asn1Encodable, TResult> constructor)
            where TResult : class
        {
            var element = RequireElement(sequence, ref sequencePosition);
            return constructor(element);
        }

        /// <summary>
        /// Read the next element of a sequence as a tagged object with the expected tag, advancing the position.
        /// </summary>
        /// <param name="sequence">The sequence.</param>
        /// <param name="sequencePosition">The position in the sequence; advanced if an element is consumed.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="state">The state passed to the constructor.</param>
        /// <param name="constructor">A function that constructs the result from the tagged object.</param>
        /// <returns>The result.</returns>
        /// <exception cref="InvalidOperationException">There are no more elements in the sequence.</exception>
        public static TResult ReadContextTagged<TState, TResult>(Asn1Sequence sequence, ref int sequencePosition,
            int tagNo, TState state, Func<Asn1TaggedObject, TState, TResult> constructor)
        {
            return ReadTagged(sequence, ref sequencePosition, Asn1Tags.ContextSpecific, tagNo, state, constructor);
        }

        /// <summary>
        /// Read the next element of a sequence as a tagged object with the expected tag, advancing the position.
        /// </summary>
        /// <param name="sequence">The sequence.</param>
        /// <param name="sequencePosition">The position in the sequence; advanced if an element is consumed.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="state">The state passed to the constructor.</param>
        /// <param name="constructor">A function that constructs the result from the tagged object.</param>
        /// <returns>The result.</returns>
        /// <exception cref="InvalidOperationException">There are no more elements in the sequence.</exception>
        public static TResult ReadTagged<TState, TResult>(Asn1Sequence sequence, ref int sequencePosition, int tagClass,
            int tagNo, TState state, Func<Asn1TaggedObject, TState, TResult> constructor)
        {
            var element = RequireElement(sequence, ref sequencePosition);
            var taggedObject = Asn1TaggedObject.GetInstance(element, tagClass, tagNo);
            return constructor(taggedObject, state);
        }

        /// <summary>
        /// Read the next element of a sequence if the constructor accepts it, advancing the position only in that case.
        /// </summary>
        /// <param name="sequence">The sequence.</param>
        /// <param name="sequencePosition">The position in the sequence; advanced if an element is consumed.</param>
        /// <param name="constructor">
        /// A function that constructs the result from the element, returning null if the element does not match.
        /// </param>
        /// <returns>The result, or null if there is no next element or it was not accepted.</returns>
        public static TResult ReadOptional<TResult>(Asn1Sequence sequence, ref int sequencePosition,
            Func<Asn1Encodable, TResult> constructor)
            where TResult : class
        {
            if (sequencePosition < sequence.Count)
            {
                var result = constructor(sequence[sequencePosition]);
                if (result != null)
                {
                    sequencePosition++;
                    return result;
                }
            }

            return null;
        }

        /// <summary>
        /// Read the next element of a sequence if it is a tagged object with the expected tag, advancing the position
        /// only in that case.
        /// </summary>
        /// <param name="sequence">The sequence.</param>
        /// <param name="sequencePosition">The position in the sequence; advanced if an element is consumed.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="state">The state passed to the constructor.</param>
        /// <param name="constructor">A function that constructs the result from the tagged object.</param>
        /// <returns>The result, or null if there is no next element or it does not have the expected tag.</returns>
        public static TResult ReadOptionalContextTagged<TState, TResult>(Asn1Sequence sequence,
            ref int sequencePosition, int tagNo, TState state, Func<Asn1TaggedObject, TState, TResult> constructor)
            where TResult : class
        {
            return ReadOptionalTagged(sequence, ref sequencePosition, Asn1Tags.ContextSpecific, tagNo, state,
                constructor);
        }

        /// <summary>
        /// Read the next element of a sequence if it is a tagged object with the expected tag, advancing the position
        /// only in that case.
        /// </summary>
        /// <param name="sequence">The sequence.</param>
        /// <param name="sequencePosition">The position in the sequence; advanced if an element is consumed.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="state">The state passed to the constructor.</param>
        /// <param name="constructor">A function that constructs the result from the tagged object.</param>
        /// <returns>The result, or null if there is no next element or it does not have the expected tag.</returns>
        public static TResult ReadOptionalTagged<TState, TResult>(Asn1Sequence sequence, ref int sequencePosition,
            int tagClass, int tagNo, TState state, Func<Asn1TaggedObject, TState, TResult> constructor)
            where TResult : class
        {
            if (sequencePosition < sequence.Count &&
                TryGetOptionalTagged(sequence[sequencePosition], tagClass, tagNo, state, out var result, constructor))
            {
                sequencePosition++;
                return result;
            }

            return null;
        }

        /// <summary>
        /// Try to read the next element of a sequence if it is a tagged object with the expected tag, advancing the
        /// position only in that case.
        /// </summary>
        /// <param name="sequence">The sequence.</param>
        /// <param name="sequencePosition">The position in the sequence; advanced if an element is consumed.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="state">The state passed to the constructor.</param>
        /// <param name="result">On success, the result.</param>
        /// <param name="constructor">A function that constructs the result from the tagged object.</param>
        /// <returns>true if an element was read, false otherwise.</returns>
        public static bool TryReadOptionalContextTagged<TState, TResult>(Asn1Sequence sequence,
            ref int sequencePosition, int tagNo, TState state, out TResult result,
            Func<Asn1TaggedObject, TState, TResult> constructor)
        {
            return TryReadOptionalTagged(sequence, ref sequencePosition, Asn1Tags.ContextSpecific, tagNo,
                state, out result, constructor);
        }

        /// <summary>
        /// Try to read the next element of a sequence if it is a tagged object with the expected tag, advancing the
        /// position only in that case.
        /// </summary>
        /// <param name="sequence">The sequence.</param>
        /// <param name="sequencePosition">The position in the sequence; advanced if an element is consumed.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="state">The state passed to the constructor.</param>
        /// <param name="result">On success, the result.</param>
        /// <param name="constructor">A function that constructs the result from the tagged object.</param>
        /// <returns>true if an element was read, false otherwise.</returns>
        public static bool TryReadOptionalTagged<TState, TResult>(Asn1Sequence sequence, ref int sequencePosition,
            int tagClass, int tagNo, TState state, out TResult result,
            Func<Asn1TaggedObject, TState, TResult> constructor)
        {
            if (sequencePosition < sequence.Count &&
                TryGetOptionalTagged(sequence[sequencePosition], tagClass, tagNo, state, out result, constructor))
            {
                sequencePosition++;
                return true;
            }

            result = default;
            return false;
        }

        private static Asn1Encodable RequireElement(Asn1Sequence sequence, ref int sequencePosition)
        {
            if (sequencePosition < 0)
                throw new ArgumentOutOfRangeException(nameof(sequencePosition));
            if (sequencePosition >= sequence.Count)
                throw new ArgumentException("Premature end of sequence", nameof(sequence));

            return sequence[sequencePosition++];
        }

        #endregion
    }
}
