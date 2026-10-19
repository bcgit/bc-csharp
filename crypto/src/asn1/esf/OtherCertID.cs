using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// <code>
    /// OtherCertID ::= SEQUENCE {
    /// 	otherCertHash OtherHash,
    /// 	issuerSerial IssuerSerial OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public class OtherCertID
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OtherCertID"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OtherCertID"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OtherCertID"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OtherCertID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherCertID otherCertID)
                return otherCertID;
            return new OtherCertID(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OtherCertID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherCertID"/>.</returns>
        public static OtherCertID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherCertID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="OtherCertID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherCertID"/>.</returns>
        public static OtherCertID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherCertID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly OtherHash m_otherCertHash;
        private readonly IssuerSerial m_issuerSerial;

        private OtherCertID(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_otherCertHash = Asn1Utilities.Read(seq, ref pos, OtherHash.GetInstance);
            m_issuerSerial = Asn1Utilities.ReadOptional(seq, ref pos, IssuerSerial.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="OtherCertID"/>.</summary>
        /// <param name="otherCertHash">The other cert hash.</param>
        public OtherCertID(OtherHash otherCertHash)
            : this(otherCertHash, null)
        {
        }

        /// <summary>Create a new <see cref="OtherCertID"/>.</summary>
        /// <param name="otherCertHash">The other cert hash.</param>
        /// <param name="issuerSerial">The issuer serial.</param>
        public OtherCertID(OtherHash otherCertHash, IssuerSerial issuerSerial)
        {
            m_otherCertHash = otherCertHash ?? throw new ArgumentNullException(nameof(otherCertHash));
            m_issuerSerial = issuerSerial;
        }

        /// <summary>Gets the other cert hash.</summary>
        public OtherHash OtherCertHash => m_otherCertHash;

        public IssuerSerial IssuerSerial => m_issuerSerial;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_otherCertHash);
            v.AddOptional(m_issuerSerial);
            return new DerSequence(v);
        }
    }
}
