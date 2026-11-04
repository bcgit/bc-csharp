using System;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The SafeBag structure of PKCS#12.</summary>
    public class SafeBag
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="SafeBag"/> from the given object.</summary>
        /// <param name="obj">An <see cref="SafeBag"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="SafeBag"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SafeBag GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SafeBag safeBag)
                return safeBag;
            return new SafeBag(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="SafeBag"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SafeBag"/>.</returns>
        public static SafeBag GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SafeBag(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="SafeBag"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SafeBag"/>.</returns>
        public static SafeBag GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SafeBag(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_bagID;
        private readonly Asn1Encodable m_bagValue;
        private readonly Asn1Set m_bagAttributes;

        private SafeBag(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_bagID = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_bagValue = Asn1Utilities.ReadContextTagged(seq, ref pos, 0, true,
                (taggedObject, declaredExplicit) => taggedObject.GetExplicitBaseObject());
            m_bagAttributes = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Set.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="SafeBag"/>.</summary>
        /// <param name="oid">The object identifier.</param>
        /// <param name="obj">The object.</param>
        // TODO[api] Remove as redundant
        public SafeBag(DerObjectIdentifier oid, Asn1Object obj)
            : this(oid, obj, null)
        {
        }

        /// <summary>Create a new <see cref="SafeBag"/>.</summary>
        /// <param name="oid">The object identifier.</param>
        /// <param name="obj">The object.</param>
        /// <param name="bagAttributes">The bag attributes.</param>
        // TODO[api] Remove as redundant
        public SafeBag(DerObjectIdentifier oid, Asn1Object obj, Asn1Set bagAttributes)
        {
            m_bagID = oid ?? throw new ArgumentNullException(nameof(oid));
            m_bagValue = obj ?? throw new ArgumentNullException(nameof(obj));
            m_bagAttributes = bagAttributes;
        }

        /// <summary>Create a new <see cref="SafeBag"/>.</summary>
        /// <param name="bagID">The bag ID.</param>
        /// <param name="bagValue">The bag value.</param>
        public SafeBag(DerObjectIdentifier bagID, Asn1Encodable bagValue)
            : this(bagID, bagValue, null)
        {
        }

        /// <summary>Create a new <see cref="SafeBag"/>.</summary>
        /// <param name="bagID">The bag ID.</param>
        /// <param name="bagValue">The bag value.</param>
        /// <param name="bagAttributes">The bag attributes.</param>
        public SafeBag(DerObjectIdentifier bagID, Asn1Encodable bagValue, Asn1Set bagAttributes)
        {
            m_bagID = bagID ?? throw new ArgumentNullException(nameof(bagID));
            m_bagValue = bagValue ?? throw new ArgumentNullException(nameof(bagValue));
            m_bagAttributes = bagAttributes;
        }

        /// <summary>Gets the bag ID.</summary>
        public DerObjectIdentifier BagID => m_bagID;

        /// <summary>Gets the bag value.</summary>
        // TODO[api] Return Asn1Encodable (and obsolete BagValueEncodable)
        public Asn1Object BagValue => m_bagValue.ToAsn1Object();

        /// <summary>Gets the bag value encodable.</summary>
        public Asn1Encodable BagValueEncodable => m_bagValue;

        /// <summary>Gets the bag attributes.</summary>
        public Asn1Set BagAttributes => m_bagAttributes;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            var taggedBagValue = new DerTaggedObject(isExplicit: true, 0, m_bagValue);

            return m_bagAttributes == null
                ?   new DerSequence(m_bagID, taggedBagValue)
                :   new DerSequence(m_bagID, taggedBagValue, m_bagAttributes);
        }
    }
}
