using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <remarks><code>extendedKeyUsage ::= Sequence SIZE (1..MAX) OF KeyPurposeId</code></remarks>
    public class ExtendedKeyUsage
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="ExtendedKeyUsage"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ExtendedKeyUsage"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ExtendedKeyUsage"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ExtendedKeyUsage GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ExtendedKeyUsage extendedKeyUsage)
                return extendedKeyUsage;
            // TODO[api] Remove this case
            if (obj is X509Extension x509Extension)
                return GetInstance(X509Extension.ConvertValueToObject(x509Extension));
            return new ExtendedKeyUsage(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="ExtendedKeyUsage"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ExtendedKeyUsage"/>.</returns>
        // TODO[api] Standardize parameter names
        public static ExtendedKeyUsage GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new ExtendedKeyUsage(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="ExtendedKeyUsage"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ExtendedKeyUsage"/>.</returns>
        public static ExtendedKeyUsage GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ExtendedKeyUsage(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public static ExtendedKeyUsage FromExtensions(X509Extensions extensions) =>
            GetInstance(X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.ExtendedKeyUsage));

        private readonly HashSet<DerObjectIdentifier> m_usageTable = new HashSet<DerObjectIdentifier>();

        // TODO[asn1] Tighten to DLSequence if/when safe
        private readonly DerSequence m_elements;

        private ExtendedKeyUsage(Asn1Sequence seq)
        {
            if (seq.Count < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(seq));

            m_elements = DerSequence.Map(seq, DerObjectIdentifier.GetInstance);

            foreach (DerObjectIdentifier element in m_elements)
            {
                m_usageTable.Add(element);
            }
        }

        /// <summary>Create a new <see cref="ExtendedKeyUsage"/>.</summary>
        /// <param name="usages">The usages.</param>
        public ExtendedKeyUsage(params KeyPurposeID[] usages)
        {
            if (Arrays.IsNullOrContainsNull(usages))
                throw new ArgumentNullException(nameof(usages), "cannot be null, or contain null");
            if (usages.Length < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(usages));

            m_elements = DerSequence.FromElements(usages);

            foreach (KeyPurposeID usage in usages)
            {
                m_usageTable.Add(usage);
            }
        }

        /// <summary>Create a new <see cref="ExtendedKeyUsage"/>.</summary>
        /// <param name="usages">The usages.</param>
        public ExtendedKeyUsage(IEnumerable<DerObjectIdentifier> usages)
        {
            if (usages == null)
                throw new ArgumentNullException(nameof(usages));

            Asn1EncodableVector v = new Asn1EncodableVector();

            foreach (var oid in usages)
            {
                m_usageTable.Add(oid);
                // TODO[asn1] Avoid adding duplicates?
                v.Add(oid);
            }

            if (v.Count < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(usages));

            m_elements = DerSequence.FromVector(v);
        }

        // TODO[api] Rename 'HasKeyPurposeID(KeyPurposeID keyPurposeID)'
        public bool HasKeyPurposeId(KeyPurposeID keyPurposeId) => m_usageTable.Contains(keyPurposeId);

        /// <summary>Returns all extended key usages.</summary>
        public IList<DerObjectIdentifier> GetAllUsages() => new List<DerObjectIdentifier>(m_usageTable);

        /// <summary>Return the all usages array.</summary>
        public DerObjectIdentifier[] GetAllUsagesArray() => m_elements.MapElements(DerObjectIdentifier.GetInstance);

        /// <summary>Gets the count.</summary>
        public int Count => m_usageTable.Count;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_elements;
    }
}
