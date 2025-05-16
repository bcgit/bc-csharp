using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The extendedKeyUsage object.
     * <pre>
     *      extendedKeyUsage ::= Sequence SIZE (1..MAX) OF KeyPurposeId
     * </pre>
     */
    public class ExtendedKeyUsage
        : Asn1Encodable
    {
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

        public static ExtendedKeyUsage GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new ExtendedKeyUsage(Asn1Sequence.GetInstance(obj, explicitly));

        public static ExtendedKeyUsage GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ExtendedKeyUsage(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public static ExtendedKeyUsage FromExtensions(X509Extensions extensions)
        {
            return GetInstance(X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.ExtendedKeyUsage));
        }

        private readonly HashSet<DerObjectIdentifier> m_usageTable = new HashSet<DerObjectIdentifier>();
        private readonly Asn1Sequence m_seq;

        private ExtendedKeyUsage(Asn1Sequence seq)
        {
            m_seq = seq;

            foreach (Asn1Encodable element in seq)
            {
                DerObjectIdentifier oid = DerObjectIdentifier.GetInstance(element);

                m_usageTable.Add(oid);
            }
        }

        public ExtendedKeyUsage(params KeyPurposeID[] usages)
        {
            m_seq = new DerSequence(usages);

            foreach (KeyPurposeID usage in usages)
            {
                m_usageTable.Add(usage);
            }
        }

        public ExtendedKeyUsage(IEnumerable<DerObjectIdentifier> usages)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            foreach (var oid in usages)
            {
                v.Add(oid);
                m_usageTable.Add(oid);
            }

            m_seq = new DerSequence(v);
        }

        // TODO[api] Rename 'HasKeyPurposeID(KeyPurposeID keyPurposeID)'
        public bool HasKeyPurposeId(KeyPurposeID keyPurposeId) => m_usageTable.Contains(keyPurposeId);

        /**
         * Returns all extended key usages.
         * The returned ArrayList contains DerObjectIdentifier instances.
         * @return An ArrayList with all key purposes.
         */
        public IList<DerObjectIdentifier> GetAllUsages() => new List<DerObjectIdentifier>(m_usageTable);

        public DerObjectIdentifier[] GetAllUsagesArray() => m_seq.MapElements(DerObjectIdentifier.GetInstance);

        public int Count => m_usageTable.Count;

        public override Asn1Object ToAsn1Object() => m_seq;
    }
}
