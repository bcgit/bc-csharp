using System;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The CertBag structure of PKCS#12.</summary>
    public class CertBag
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertBag"/> from the given object.</summary>
        /// <param name="obj">An <see cref="CertBag"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="CertBag"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertBag GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertBag certBag)
                return certBag;
            return new CertBag(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertBag"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertBag"/>.</returns>
        public static CertBag GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertBag(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CertBag"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertBag"/>.</returns>
        public static CertBag GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertBag(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_certID;
        private readonly Asn1Encodable m_certValue;

        private CertBag(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certID = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_certValue = Asn1Utilities.ReadContextTagged(seq, ref pos, 0, true,
                (taggedObject, declaredExplicit) => taggedObject.GetExplicitBaseObject());

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="CertBag"/>.</summary>
        /// <param name="certID">The cert ID.</param>
        /// <param name="certValue">The cert value.</param>
        // TODO[api] Remove as redundant
        public CertBag(DerObjectIdentifier certID, Asn1Object certValue)
        {
            m_certID = certID ?? throw new ArgumentNullException(nameof(certID));
            m_certValue = certValue ?? throw new ArgumentNullException(nameof(certValue));
        }

        /// <summary>Create a new <see cref="CertBag"/>.</summary>
        /// <param name="certID">The cert ID.</param>
        /// <param name="certValue">The cert value.</param>
        public CertBag(DerObjectIdentifier certID, Asn1Encodable certValue)
        {
            m_certID = certID ?? throw new ArgumentNullException(nameof(certID));
            m_certValue = certValue ?? throw new ArgumentNullException(nameof(certValue));
        }

        /// <summary>Gets the cert ID.</summary>
        public virtual DerObjectIdentifier CertID => m_certID;

        /// <summary>Gets the cert value.</summary>
        // TODO[api] Return Asn1Encodable (and obsolete CertValueEncodable)
        public virtual Asn1Object CertValue => m_certValue.ToAsn1Object();

        /// <summary>Gets the cert value encodable.</summary>
        public virtual Asn1Encodable CertValueEncodable => m_certValue;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_certID, new DerTaggedObject(0, m_certValue));
    }
}
