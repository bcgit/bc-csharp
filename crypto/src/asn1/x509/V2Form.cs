using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The V2Form structure of RFC 5755.</summary>
    public class V2Form
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="V2Form"/> from the given object.</summary>
        /// <param name="obj">An <see cref="V2Form"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="V2Form"/>, or null if <paramref name="obj"/> is null.</returns>
        public static V2Form GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is V2Form v2Form)
                return v2Form;
            return new V2Form(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="V2Form"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="V2Form"/>.</returns>
        public static V2Form GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new V2Form(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="V2Form"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="V2Form"/>, or null if <paramref name="element"/> is null.</returns>
        public static V2Form GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is V2Form v2Form)
                return v2Form;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new V2Form(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="V2Form"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="V2Form"/>.</returns>
        public static V2Form GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new V2Form(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly GeneralNames m_issuerName;
        private readonly IssuerSerial m_baseCertificateID;
        private readonly ObjectDigestInfo m_objectDigestInfo;

        private V2Form(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_issuerName = Asn1Utilities.ReadOptional(seq, ref pos, GeneralNames.GetOptional);
            m_baseCertificateID = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, IssuerSerial.GetTagged);
            m_objectDigestInfo = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, ObjectDigestInfo.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="V2Form"/>.</summary>
        /// <param name="issuerName">The issuer name.</param>
        public V2Form(GeneralNames issuerName)
            : this(issuerName, null, null)
        {
        }

        /// <summary>Create a new <see cref="V2Form"/>.</summary>
        /// <param name="issuerName">The issuer name.</param>
        /// <param name="baseCertificateID">The base certificate ID.</param>
        public V2Form(GeneralNames issuerName, IssuerSerial baseCertificateID)
            : this(issuerName, baseCertificateID, null)
        {
        }

        /// <summary>Create a new <see cref="V2Form"/>.</summary>
        /// <param name="issuerName">The issuer name.</param>
        /// <param name="objectDigestInfo">The object digest info.</param>
        public V2Form(GeneralNames issuerName, ObjectDigestInfo objectDigestInfo)
            : this(issuerName, null, objectDigestInfo)
        {
        }

        /// <summary>Create a new <see cref="V2Form"/>.</summary>
        /// <param name="issuerName">The issuer name.</param>
        /// <param name="baseCertificateID">The base certificate ID.</param>
        /// <param name="objectDigestInfo">The object digest info.</param>
        public V2Form(GeneralNames issuerName, IssuerSerial baseCertificateID, ObjectDigestInfo objectDigestInfo)
        {
            m_issuerName = issuerName;
            m_baseCertificateID = baseCertificateID;
            m_objectDigestInfo = objectDigestInfo;
        }

        /// <summary>Gets the issuer name.</summary>
        public GeneralNames IssuerName => m_issuerName;

        /// <summary>Gets the base certificate ID.</summary>
        public IssuerSerial BaseCertificateID => m_baseCertificateID;

        public ObjectDigestInfo ObjectDigestInfo => m_objectDigestInfo;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  V2Form ::= Sequence {
         *       issuerName            GeneralNames  OPTIONAL,
         *       baseCertificateID     [0] IssuerSerial  OPTIONAL,
         *       objectDigestInfo      [1] ObjectDigestInfo  OPTIONAL
         *         -- issuerName MUST be present in this profile
         *         -- baseCertificateID and objectDigestInfo MUST NOT
         *         -- be present in this profile
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptional(m_issuerName);
            v.AddOptionalTagged(false, 0, m_baseCertificateID);
            v.AddOptionalTagged(false, 1, m_objectDigestInfo);
            return new DerSequence(v);
        }
    }
}
