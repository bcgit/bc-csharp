using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The ResponderID choice of RFC 6960.</summary>
    public class ResponderID
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="ResponderID"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ResponderID"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ResponderID"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ResponderID GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="ResponderID"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ResponderID"/>.</returns>
        public static ResponderID GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            Asn1Utilities.GetInstanceChoice(obj, isExplicit, GetInstance);

        /// <summary>Return an <see cref="ResponderID"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="ResponderID"/>, or null if <paramref name="element"/> is null.</returns>
        public static ResponderID GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is ResponderID responderID)
                return responderID;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(1))
                    return new ResponderID(X509Name.GetTagged(taggedObject, true));

                if (taggedObject.HasContextTag(2))
                    return new ResponderID(Asn1OctetString.GetTagged(taggedObject, true));
            }

            // TODO[api] Remove this handler
            if (element is Asn1OctetString asn1OctetString)
                return new ResponderID(asn1OctetString);

            // TODO[api] Remove this handler
            X509Name byName = X509Name.GetOptional(element);
            if (byName != null)
                return new ResponderID(byName);

            return null;
        }

        /// <summary>Return an <see cref="ResponderID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ResponderID"/>.</returns>
        public static ResponderID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable m_id;

        /// <summary>Create a new <see cref="ResponderID"/>.</summary>
        /// <param name="id">The id.</param>
        public ResponderID(Asn1OctetString id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

        /// <summary>Create a new <see cref="ResponderID"/>.</summary>
        /// <param name="id">The id.</param>
        public ResponderID(X509Name id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

        /// <summary>Return the key hash.</summary>
        public virtual byte[] GetKeyHash() => (m_id as Asn1OctetString)?.GetOctets();

        public virtual X509Name Name
        {
            get
            {
                if (m_id is Asn1OctetString)
                    return null;

                return X509Name.GetInstance(m_id);
            }
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * ResponderID ::= CHOICE {
         *      byName          [1] Name,
         *      byKey           [2] KeyHash }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            if (m_id is Asn1OctetString asn1OctetString)
                return new DerTaggedObject(true, 2, asn1OctetString);

            return new DerTaggedObject(true, 1, m_id);
        }
    }
}
