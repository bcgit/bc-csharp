using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /**
     * A Null object.
     */
    public abstract class Asn1Null
        : Asn1Object
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(Asn1Null), Asn1Tags.Null) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets());
            }
        }

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
                    throw new ArgumentException("failed to construct NULL from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj));
        }

        public static Asn1Null GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (Asn1Null)Meta.Instance.GetContextInstance(taggedObject, declaredExplicit);
        }

        public static Asn1Null GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Asn1Null existing)
                return existing;

            return null;
        }

        public static Asn1Null GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (Asn1Null)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        internal Asn1Null()
        {
        }

        public override string ToString()
        {
            return "NULL";
        }

        internal static Asn1Null CreatePrimitive(byte[] contents)
        {
            if (0 != contents.Length)
                throw new InvalidOperationException("malformed NULL encoding encountered");

            return DerNull.Instance;
        }
    }
}
