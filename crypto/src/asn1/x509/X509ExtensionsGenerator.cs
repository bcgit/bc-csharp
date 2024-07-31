using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <remarks>Generator for X.509 extensions</remarks>
    public class X509ExtensionsGenerator
    {
        private Dictionary<DerObjectIdentifier, X509Extension> m_extensions =
            new Dictionary<DerObjectIdentifier, X509Extension>();
        private List<DerObjectIdentifier> m_ordering = new List<DerObjectIdentifier>();

        private static readonly HashSet<DerObjectIdentifier> m_dupsAllowed = new HashSet<DerObjectIdentifier>()
        {
            X509Extensions.SubjectAlternativeName,
            X509Extensions.IssuerAlternativeName,
            X509Extensions.SubjectDirectoryAttributes,
            X509Extensions.CertificateIssuer
        };

        /// <summary>Reset the generator</summary>
        public void Reset()
        {
            m_extensions = new Dictionary<DerObjectIdentifier, X509Extension>();
            m_ordering = new List<DerObjectIdentifier>();
        }

        /// <summary>
        /// Add an extension with the given oid and the passed in value to be included
        /// in the OCTET STRING associated with the extension.
        /// </summary>
        /// <param name="oid">OID for the extension.</param>
        /// <param name="critical">True if critical, false otherwise.</param>
        /// <param name="extValue">The ASN.1 object to be included in the extension.</param>
        public void AddExtension(DerObjectIdentifier oid, bool critical, Asn1Encodable extValue)
        {
            byte[] encoded;
            try
            {
                encoded = extValue.GetDerEncoded();
            }
            catch (Exception e)
            {
                throw new ArgumentException("error encoding value: " + e);
            }

            this.AddExtension(oid, critical, encoded);
        }

        /// <summary>
        /// Add an extension with the given oid and the passed in byte array to be wrapped
        /// in the OCTET STRING associated with the extension.
        /// </summary>
        /// <param name="oid">OID for the extension.</param>
        /// <param name="critical">True if critical, false otherwise.</param>
        /// <param name="extValue">The byte array to be wrapped.</param>
        public void AddExtension(DerObjectIdentifier oid, bool critical, byte[] extValue)
        {
            if (!m_extensions.TryGetValue(oid, out X509Extension existingExtension))
            {
                m_ordering.Add(oid);
                m_extensions.Add(oid, new X509Extension(critical, DerOctetString.FromContents(extValue)));
                return;
            }

            if (!m_dupsAllowed.Contains(oid))
                throw new ArgumentException("extension " + oid + " already added");

            Asn1Sequence seq1 = Asn1Sequence.GetInstance(existingExtension.Value.GetOctets());
            Asn1Sequence seq2 = Asn1Sequence.GetInstance(extValue);

            var concat = DerSequence.Concatenate(seq1, seq2);

            m_extensions[oid] = new X509Extension(
                existingExtension.IsCritical | critical,
                new DerOctetString(concat.GetEncoded(Asn1Encodable.Der)));
        }

        public void AddExtensions(X509Extensions extensions)
        {
            foreach (DerObjectIdentifier ident in extensions.ExtensionOids)
            {
                X509Extension ext = extensions.GetExtension(ident);
                AddExtension(ident, ext.critical, ext.Value.GetOctets());
            }
        }

        /// <summary>Return true if there are no extension present in this generator.</summary>
        /// <returns>True if empty, false otherwise</returns>
        public bool IsEmpty
        {
            get { return m_ordering.Count < 1; }
        }

        /// <summary>Generate an X509Extensions object based on the current state of the generator.</summary>
        /// <returns>An <c>X509Extensions</c> object</returns>
        public X509Extensions Generate()
        {
            return new X509Extensions(m_ordering, m_extensions);
        }

        internal void AddExtension(DerObjectIdentifier oid, X509Extension x509Extension)
        {
            if (m_extensions.ContainsKey(oid))
                throw new ArgumentException("extension " + oid + " already added");

            m_ordering.Add(oid);
            m_extensions.Add(oid, x509Extension);
        }
    }
}
