using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * GenMsg:    {id-it TBD1}, SEQUENCE SIZE (1..MAX) OF CRLStatus
     * GenRep:    {id-it TBD2}, SEQUENCE SIZE (1..MAX) OF
     * CertificateList  |  &lt; absent &gt;
     * <p>
     * CRLSource ::= CHOICE {
     * dpn          [0] DistributionPointName,
     * issuer       [1] GeneralNames }
     * </p>
     */
    public class CrlSource
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="CrlSource"/> from the given object.</summary>
        /// <param name="obj">An <see cref="CrlSource"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="CrlSource"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CrlSource GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="CrlSource"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlSource"/>.</returns>
        public static CrlSource GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="CrlSource"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="CrlSource"/>, or null if <paramref name="element"/> is null.</returns>
        public static CrlSource GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CrlSource crlSource)
                return crlSource;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(0))
                    return new CrlSource(dpn: DistributionPointName.GetTagged(taggedObject, true), issuer: null);

                if (taggedObject.HasContextTag(1))
                    return new CrlSource(dpn: null, issuer: GeneralNames.GetTagged(taggedObject, true));
            }

            return null;
        }

        /// <summary>Return an <see cref="CrlSource"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlSource"/>.</returns>
        public static CrlSource GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly DistributionPointName m_dpn;
        private readonly GeneralNames m_issuer;

        /// <summary>Create a new <see cref="CrlSource"/>.</summary>
        /// <param name="dpn">The dpn.</param>
        /// <param name="issuer">The issuer.</param>
        public CrlSource(DistributionPointName dpn, GeneralNames issuer)
        {
            if ((dpn == null) == (issuer == null))
                throw new ArgumentException("either dpn or issuer must be set");

            m_dpn = dpn;
            m_issuer = issuer;
        }

        /// <summary>Gets the dpn.</summary>
        public virtual DistributionPointName Dpn => m_dpn;

        /// <summary>Gets the issuer.</summary>
        public virtual GeneralNames Issuer => m_issuer;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            if (m_dpn != null)
                return new DerTaggedObject(true, 0, m_dpn);
            if (m_issuer != null)
                return new DerTaggedObject(true, 1, m_issuer);
            throw new InvalidOperationException();
        }
    }
}
