using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * <pre>
     *     Extensions        ::=   SEQUENCE SIZE (1..MAX) OF Extension
     *
     *     Extension         ::=   SEQUENCE {
     *        extnId            EXTENSION.&amp;id ({ExtensionSet}),
     *        critical          BOOLEAN DEFAULT FALSE,
     *        extnValue         OCTET STRING }
     * </pre>
     */
    public sealed class Extensions
        : Asn1Encodable
    {
        public static Extension GetExtension(Extensions extensions, DerObjectIdentifier oid) =>
            extensions?.GetExtension(oid);

        public static Asn1Object GetExtensionParsedValue(Extensions extensions, DerObjectIdentifier oid) =>
            extensions?.GetExtensionParsedValue(oid);

        public static Asn1OctetString GetExtensionValue(Extensions extensions, DerObjectIdentifier oid) =>
            extensions?.GetExtensionValue(oid);

        public static Extensions GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Extensions extensions)
                return extensions;
            return new Extensions(Asn1Sequence.GetInstance(obj));
        }

        public static Extensions GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Extensions(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Extensions GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Extensions existing)
                return existing;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new Extensions(asn1Sequence);

            return null;
        }

        public static Extensions GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Extensions(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Dictionary<DerObjectIdentifier, Extension> m_extensions = new Dictionary<DerObjectIdentifier, Extension>();
        private readonly List<DerObjectIdentifier> m_ordering;

        private Extensions(Asn1Sequence seq)
        {
            m_ordering = new List<DerObjectIdentifier>();

            // Don't require non-empty sequence; we see empty extension blocks in the wild

            foreach (var extension in CollectionUtilities.Select(seq, Extension.GetInstance))
            {
                var extnID = extension.ExtnID;
                if (!CollectionUtilities.TryAdd(m_extensions, extnID, extension))
                {
                    //if (!Properties.isOverrideSet("org.bouncycastle.x509.ignore_repeated_extensions"))
                        throw new ArgumentException("repeated extension found: " + extnID, nameof(seq));
                }

                m_ordering.Add(extnID);
            }
        }

        public Extensions(Extension extension)
        {
            var extnID = extension.ExtnID;

            m_extensions.Add(extnID, extension);
            m_ordering = new List<DerObjectIdentifier>{ extnID };
        }

        public Extensions(Extension[] extensions)
        {
            if (Arrays.IsNullOrEmpty(extensions))
                throw new ArgumentException("extension array cannot be null or empty", nameof(extensions));

            m_ordering = new List<DerObjectIdentifier>(extensions.Length);

            for (int i = 0; i < extensions.Length; ++i)
            {
                var extension = extensions[i];
                var extnID = extension.ExtnID;

                m_extensions.Add(extnID, extension);
                m_ordering.Add(extnID);
            }
        }

        public bool Equivalent(Extensions other)
        {
            if (m_extensions.Count != other.m_extensions.Count)
                return false;

            foreach (var entry in m_extensions)
            {
                if (!entry.Value.Equals(other.GetExtension(entry.Key)))
                    return false;
            }

            return true;
        }

        public DerObjectIdentifier[] GetCriticalExtensionOids() => GetExtensionOids(true);

        public Extension GetExtension(DerObjectIdentifier oid) => CollectionUtilities.GetValueOrNull(m_extensions, oid);

        public DerObjectIdentifier[] GetExtensionOids() => m_ordering.ToArray();

        public Asn1Object GetExtensionParsedValue(DerObjectIdentifier oid) => GetExtension(oid)?.GetParsedValue();

        public Asn1OctetString GetExtensionValue(DerObjectIdentifier oid) => GetExtension(oid)?.ExtnValue;

        public DerObjectIdentifier[] GetNonCriticalExtensionOids() => GetExtensionOids(false);

        public bool HasAnyCriticalExtensions()
        {
            foreach (var extension in m_extensions.Values)
            {
                if (extension.Critical.IsTrue)
                    return true;
            }
            return false;
        }

        public IEnumerable<DerObjectIdentifier> ExtensionOids => CollectionUtilities.Proxy(m_ordering);

        /**
         * <pre>
         *     Extensions        ::=   SEQUENCE SIZE (1..MAX) OF Extension
         *
         *     Extension         ::=   SEQUENCE {
         *        extnId            EXTENSION.&amp;id ({ExtensionSet}),
         *        critical          BOOLEAN DEFAULT FALSE,
         *        extnValue         OCTET STRING }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(m_ordering.Count);

            foreach (var extnID in m_ordering)
            {
                v.Add(m_extensions[extnID]);
            }

            return new DerSequence(v);
        }

        private DerObjectIdentifier[] GetExtensionOids(bool isCritical)
        {
            var result = new List<DerObjectIdentifier>();

            foreach (var extnID in m_ordering)
            {
                if (m_extensions[extnID].Critical.IsTrue == isCritical)
                {
                    result.Add(extnID);
                }
            }

            return result.ToArray();
        }
    }
}
