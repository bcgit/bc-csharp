using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The TBSRequest structure of RFC 6960.</summary>
    public class TbsRequest
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="TbsRequest"/> from the given object.</summary>
        /// <param name="obj">An <see cref="TbsRequest"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="TbsRequest"/>, or null if <paramref name="obj"/> is null.</returns>
        public static TbsRequest GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TbsRequest tbsRequest)
                return tbsRequest;
            return new TbsRequest(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="TbsRequest"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TbsRequest"/>.</returns>
        public static TbsRequest GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new TbsRequest(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="TbsRequest"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TbsRequest"/>.</returns>
        public static TbsRequest GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TbsRequest(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private static readonly DerInteger V1 = DerInteger.Zero;

        private readonly DerInteger m_version;
        private readonly bool m_versionPresent;
        private readonly GeneralName m_requestorName;
        private readonly Asn1Sequence m_requestList;
        private readonly X509Extensions m_requestExtensions;

        /// <summary>Create a new <see cref="TbsRequest"/>.</summary>
        /// <param name="requestorName">The requestor name.</param>
        /// <param name="requestList">The request list.</param>
        /// <param name="requestExtensions">The request extensions.</param>
        public TbsRequest(GeneralName requestorName, Asn1Sequence requestList, X509Extensions requestExtensions)
        {
            m_version = V1;
            m_versionPresent = false;
            m_requestorName = requestorName;
            m_requestList = requestList ?? throw new ArgumentNullException(nameof(requestList));
            m_requestExtensions = requestExtensions;
        }

        private TbsRequest(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            {
                DerInteger version = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, DerInteger.GetTagged);

                m_version = version ?? V1;
                m_versionPresent = version != null;
            }

            m_requestorName = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, GeneralName.GetTagged);
            m_requestList = Asn1Utilities.Read(seq, ref pos, Asn1Sequence.GetInstance);
            m_requestExtensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, X509Extensions.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        /// <summary>Gets the requestor name.</summary>
        public GeneralName RequestorName => m_requestorName;

        /// <summary>Gets the request list.</summary>
        public Asn1Sequence RequestList => m_requestList;

        /// <summary>Gets the request extensions.</summary>
        public X509Extensions RequestExtensions => m_requestExtensions;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * TBSRequest      ::=     Sequence {
         *     version             [0]     EXPLICIT Version DEFAULT v1,
         *     requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
         *     requestList                 Sequence OF Request,
         *     requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);

            //
            // if default don't include - unless explicitly provided. Not strictly correct
            // but required for some requests
            //
            if (m_versionPresent || !V1.Equals(m_version))
            {
                v.Add(new DerTaggedObject(true, 0, m_version));
            }

            v.AddOptionalTagged(true, 1, m_requestorName);
            v.Add(m_requestList);
            v.AddOptionalTagged(true, 2, m_requestExtensions);
            return new DerSequence(v);
        }
    }
}
