using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The SingleResponse structure of RFC 6960: the status of one certificate.</summary>
    public class SingleResponse
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="SingleResponse"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SingleResponse"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SingleResponse"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SingleResponse GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SingleResponse singleResponse)
                return singleResponse;
#pragma warning disable CS0618 // Type or member is obsolete
            return new SingleResponse(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="SingleResponse"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SingleResponse"/>.</returns>
        public static SingleResponse GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SingleResponse(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="SingleResponse"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SingleResponse"/>.</returns>
        public static SingleResponse GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SingleResponse(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly CertID m_certID;
        private readonly CertStatus m_certStatus;
        private readonly Asn1GeneralizedTime m_thisUpdate;
        private readonly Asn1GeneralizedTime m_nextUpdate;
        private readonly X509Extensions m_singleExtensions;

        /// <summary>Create a new <see cref="SingleResponse"/>.</summary>
        /// <param name="certID">The cert ID.</param>
        /// <param name="certStatus">The cert status.</param>
        /// <param name="thisUpdate">The this update.</param>
        /// <param name="nextUpdate">The next update.</param>
        /// <param name="singleExtensions">The single extensions.</param>
        public SingleResponse(CertID certID, CertStatus certStatus, Asn1GeneralizedTime thisUpdate,
            Asn1GeneralizedTime nextUpdate, X509Extensions singleExtensions)
        {
            m_certID = certID ?? throw new ArgumentNullException(nameof(certID));
            m_certStatus = certStatus ?? throw new ArgumentNullException(nameof(certStatus));
            m_thisUpdate = thisUpdate ?? throw new ArgumentNullException(nameof(thisUpdate));
            m_nextUpdate = nextUpdate;
            m_singleExtensions = singleExtensions;
        }

        /// <summary>Create a new <see cref="SingleResponse"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public SingleResponse(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count;
            if (count < 3 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_certID = Asn1Utilities.Read(seq, ref pos, CertID.GetInstance);
            m_certStatus = Asn1Utilities.Read(seq, ref pos, CertStatus.GetInstance);
            m_thisUpdate = Asn1Utilities.Read(seq, ref pos, Asn1GeneralizedTime.GetInstance);
            m_nextUpdate = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1GeneralizedTime.GetTagged);
            m_singleExtensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, X509Extensions.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the cert id.</summary>
        public CertID CertId => m_certID;

        public CertStatus CertStatus => m_certStatus;

        /// <summary>Gets the this update.</summary>
        public Asn1GeneralizedTime ThisUpdate => m_thisUpdate;

        /// <summary>Gets the next update.</summary>
        public Asn1GeneralizedTime NextUpdate => m_nextUpdate;

        /// <summary>Gets the single extensions.</summary>
        public X509Extensions SingleExtensions => m_singleExtensions;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  SingleResponse ::= Sequence {
         *          certID                       CertID,
         *          certStatus                   CertStatus,
         *          thisUpdate                   GeneralizedTime,
         *          nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
         *          singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_certID, m_certStatus, m_thisUpdate);
            v.AddOptionalTagged(true, 0, m_nextUpdate);
            v.AddOptionalTagged(true, 1, m_singleExtensions);
            return new DerSequence(v);
        }
    }
}
