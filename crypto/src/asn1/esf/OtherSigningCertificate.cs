using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// <code>
    /// OtherSigningCertificate ::= SEQUENCE {
    /// 	certs SEQUENCE OF OtherCertID,
    /// 	policies SEQUENCE OF PolicyInformation OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public class OtherSigningCertificate
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OtherSigningCertificate"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OtherSigningCertificate"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OtherSigningCertificate"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OtherSigningCertificate GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherSigningCertificate otherSigningCertificate)
                return otherSigningCertificate;
            return new OtherSigningCertificate(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OtherSigningCertificate"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherSigningCertificate"/>.</returns>
        public static OtherSigningCertificate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherSigningCertificate(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="OtherSigningCertificate"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherSigningCertificate"/>.</returns>
        public static OtherSigningCertificate GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherSigningCertificate(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_certs;
        private readonly Asn1Sequence m_policies;

        private OtherSigningCertificate(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certs = Asn1Utilities.Read(seq, ref pos, Asn1Sequence.GetInstance);
            m_policies = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Sequence.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="OtherSigningCertificate"/>.</summary>
        /// <param name="certs">The certs.</param>
        public OtherSigningCertificate(params OtherCertID[] certs)
            : this(certs, null)
        {
        }

        /// <summary>Create a new <see cref="OtherSigningCertificate"/>.</summary>
        /// <param name="certs">The certs.</param>
        /// <param name="policies">The policies.</param>
        public OtherSigningCertificate(OtherCertID[] certs, params PolicyInformation[] policies)
        {
            m_certs = DerSequence.FromElements(certs);
            m_policies = DerSequence.FromElementsOptional(policies);
        }

        /// <summary>Create a new <see cref="OtherSigningCertificate"/>.</summary>
        /// <param name="certs">The certs.</param>
        public OtherSigningCertificate(IEnumerable<OtherCertID> certs)
            : this(certs, null)
        {
        }

        /// <summary>Create a new <see cref="OtherSigningCertificate"/>.</summary>
        /// <param name="certs">The certs.</param>
        /// <param name="policies">The policies.</param>
        public OtherSigningCertificate(IEnumerable<OtherCertID> certs, IEnumerable<PolicyInformation> policies)
        {
            if (certs == null)
                throw new ArgumentNullException(nameof(certs));

            m_certs = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(certs));

            if (policies != null)
            {
                m_policies = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(policies));
            }
        }

        /// <summary>Create a new <see cref="OtherSigningCertificate"/>.</summary>
        /// <param name="certs">The certs.</param>
        /// <param name="policies">The policies.</param>
        public OtherSigningCertificate(IReadOnlyCollection<OtherCertID> certs,
            IReadOnlyCollection<PolicyInformation> policies)
        {
            if (certs == null)
                throw new ArgumentNullException(nameof(certs));

            m_certs = DerSequence.FromCollection(certs);

            if (policies != null)
            {
                m_policies = DerSequence.FromCollection(policies);
            }
        }

        /// <summary>Return the certs.</summary>
        public OtherCertID[] GetCerts() => m_certs.MapElements(OtherCertID.GetInstance);

        /// <summary>Return the policies.</summary>
        public PolicyInformation[] GetPolicies() => m_policies?.MapElements(PolicyInformation.GetInstance);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_certs);
            v.AddOptional(m_policies);
            return new DerSequence(v);
        }
    }
}
