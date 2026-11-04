using System;

using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Asn1.UA
{
    /// <summary>A public key for DSTU 4145-2002.</summary>
    public class Dstu4145PublicKey
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Dstu4145PublicKey"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="Dstu4145PublicKey"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="Dstu4145PublicKey"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Dstu4145PublicKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Dstu4145PublicKey dstu4145PublicKey)
                return dstu4145PublicKey;
            return new Dstu4145PublicKey(Asn1OctetString.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Dstu4145PublicKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Dstu4145PublicKey"/>.</returns>
        public static Dstu4145PublicKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145PublicKey(Asn1OctetString.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="Dstu4145PublicKey"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="Dstu4145PublicKey"/>, or null if <paramref name="element"/> is null.</returns>
        public static Dstu4145PublicKey GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Dstu4145PublicKey dstu4145PublicKey)
                return dstu4145PublicKey;

            Asn1OctetString asn1OctetString = Asn1OctetString.GetOptional(element);
            if (asn1OctetString != null)
                return new Dstu4145PublicKey(asn1OctetString);

            return null;
        }

        /// <summary>Return an <see cref="Dstu4145PublicKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Dstu4145PublicKey"/>.</returns>
        public static Dstu4145PublicKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145PublicKey(Asn1OctetString.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_pubKey;

        /// <summary>Create a new <see cref="Dstu4145PublicKey"/>.</summary>
        /// <param name="pubKey">The public key.</param>
        public Dstu4145PublicKey(ECPoint pubKey)
        {
            // We always use big-endian in parameter encoding
            m_pubKey = new DerOctetString(Dstu4145PointEncoder.EncodePoint(pubKey));
        }

        private Dstu4145PublicKey(Asn1OctetString pubKey)
        {
            m_pubKey = pubKey;
        }

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_pubKey;
    }
}
