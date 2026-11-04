using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>A NULL object.</summary>
    public abstract class Asn1Null
        : Asn1Object
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(Asn1Null), Asn1Tags.Null) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctetsLength());
            }
        }

        /// <summary>Return an <see cref="Asn1Null"/> from the given object.</summary>
        /// <param name="obj">An <see cref="Asn1Null"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="Asn1Null"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Asn1Null GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is Asn1Null asn1Null)
                return asn1Null;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is Asn1Null converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (Asn1Null)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct NULL from byte[]", nameof(obj), e);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), nameof(obj));
        }

        /// <summary>Return an <see cref="Asn1Null"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Asn1Null"/>.</returns>
        public static Asn1Null GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (Asn1Null)Meta.Instance.GetContextTagged(taggedObject, declaredExplicit);
        }

        /// <summary>Return an <see cref="Asn1Null"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="Asn1Null"/>, or null if <paramref name="element"/> is null.</returns>
        public static Asn1Null GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Asn1Null existing)
                return existing;

            return null;
        }

        /// <summary>Return an <see cref="Asn1Null"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Asn1Null"/>.</returns>
        public static Asn1Null GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (Asn1Null)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        internal Asn1Null()
        {
        }

        /// <inheritdoc/>
        public override string ToString() => "NULL";

        private static void CheckContentsLength(int contentsLength)
        {
            if (0 != contentsLength)
                throw new InvalidOperationException("malformed NULL encoding encountered");
        }

        internal static Asn1Null CreatePrimitive(DefiniteLengthInputStream defIn) => CreatePrimitive(defIn.Remaining);

        private static Asn1Null CreatePrimitive(int contentsLength)
        {
            CheckContentsLength(contentsLength);
            return DerNull.Instance;
        }
    }
}
