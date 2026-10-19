using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <remarks>Generator for X.509 extensions</remarks>
    public class X509ExtensionsGenerator
    {
        // TODO Store Asn1.X509.Extension values (and consolidate into a KeyedCollection)?
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

        /// <summary>
        /// Add an extension with the given oid and the passed in value to be included in the OCTET STRING associated
        /// with the extension.
        /// </summary>
        /// <param name="oid">OID for the extension.</param>
        /// <param name="critical">True if critical, false otherwise.</param>
        /// <param name="extValue">The ASN.1 object to be included in the extension.</param>
        public void AddExtension(DerObjectIdentifier oid, bool critical, IAsn1Convertible extValue) =>
            AddExtension(oid, critical, extValue.ToAsn1Object());

        /// <summary>
        /// Add an extension with the given oid and the passed in value to be included
        /// in the OCTET STRING associated with the extension.
        /// </summary>
        /// <param name="oid">OID for the extension.</param>
        /// <param name="critical">True if critical, false otherwise.</param>
        /// <param name="extValue">The ASN.1 object to be included in the extension.</param>
        public void AddExtension(DerObjectIdentifier oid, bool critical, Asn1Encodable extValue)
        {
            if (m_extensions.TryGetValue(oid, out X509Extension existingExtension))
            {
                ImplAddExtensionDup(existingExtension, oid, critical, extValue.GetEncoded(Asn1Encodable.Der));
            }
            else
            {
                ImplAddExtension(oid, new X509Extension(critical, new DerOctetString(extValue)));
            }
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
            if (m_extensions.TryGetValue(oid, out X509Extension existingExtension))
            {
                ImplAddExtensionDup(existingExtension, oid, critical, extValue);
            }
            else
            {
                ImplAddExtension(oid, new X509Extension(critical, DerOctetString.FromContents(extValue)));
            }
        }

        /// <summary>
        /// Add an extension with the given oid and the passed in byte array to be wrapped in the OCTET STRING
        /// associated with the extension.
        /// </summary>
        /// <param name="oid">OID for the extension.</param>
        /// <param name="x509Extension">The x 509 extension.</param>
        public void AddExtension(DerObjectIdentifier oid, X509Extension x509Extension)
        {
            if (HasExtension(oid))
                throw new ArgumentException("extension " + oid + " already added");

            ImplAddExtension(oid, x509Extension);
        }

        /// <summary>
        /// Add an extension with the given oid and the passed in byte array to be wrapped in the OCTET STRING
        /// associated with the extension.
        /// </summary>
        /// <param name="extension">The extension.</param>
        public void AddExtension(Extension extension) => AddExtension(extension.ExtnID, extension.GetX509Extension());

        /// <summary>Add all the extensions of a table of extensions.</summary>
        /// <param name="extensions">The extensions to add.</param>
        public void AddExtensions(X509Extensions extensions)
        {
            foreach (var oid in extensions.GetExtensionOids())
            {
                var extension = extensions.GetExtension(oid);
                AddExtension(oid, extension.IsCritical, extension.Value.GetOctets());
            }
        }

        /// <summary>Generate an X509Extensions object based on the current state of the generator.</summary>
        /// <returns>An <c>X509Extensions</c> object</returns>
        public X509Extensions Generate() => new X509Extensions(m_ordering, m_extensions);

        /// <summary>Get the extension of the given type.</summary>
        /// <param name="oid">The extension type.</param>
        /// <returns>The extension, or null if it is not present.</returns>
        public X509Extension GetExtension(DerObjectIdentifier oid) =>
            CollectionUtilities.GetValueOrNull(m_extensions, oid);

        /// <summary>Determine whether an extension of the given type is present.</summary>
        /// <param name="oid">The extension type.</param>
        /// <returns>true if it is present, false otherwise.</returns>
        public bool HasExtension(DerObjectIdentifier oid) => m_extensions.ContainsKey(oid);

        /// <summary>Return true if there are no extension present in this generator.</summary>
        /// <returns>True if empty, false otherwise</returns>
        public bool IsEmpty => m_ordering.Count < 1;

        /// <summary>Remove an extension.</summary>
        /// <param name="oid">The extension type.</param>
        /// <exception cref="InvalidOperationException">The extension is not present.</exception>
        public void RemoveExtension(DerObjectIdentifier oid)
        {
            if (!HasExtension(oid))
                throw new InvalidOperationException("extension " + oid + " not present");

            m_ordering.Remove(oid);
            m_extensions.Remove(oid);
        }

        /// <summary>Replace an extension that is already present.</summary>
        /// <param name="oid">The extension type.</param>
        /// <param name="critical">true if the extension is critical, false otherwise.</param>
        /// <param name="extValue">The new extension value.</param>
        /// <exception cref="InvalidOperationException">The extension is not present.</exception>
        public void ReplaceExtension(DerObjectIdentifier oid, bool critical, IAsn1Convertible extValue) =>
            ReplaceExtension(oid, critical, extValue.ToAsn1Object());

        /// <summary>Replace an extension that is already present.</summary>
        /// <param name="oid">The extension type.</param>
        /// <param name="critical">true if the extension is critical, false otherwise.</param>
        /// <param name="extValue">The new extension value.</param>
        /// <exception cref="InvalidOperationException">The extension is not present.</exception>
        public void ReplaceExtension(DerObjectIdentifier oid, bool critical, Asn1Encodable extValue) =>
            ReplaceExtension(oid, new X509Extension(critical, new DerOctetString(extValue)));

        /// <summary>Replace an extension that is already present.</summary>
        /// <param name="oid">The extension type.</param>
        /// <param name="critical">true if the extension is critical, false otherwise.</param>
        /// <param name="extValue">The new extension value.</param>
        /// <exception cref="InvalidOperationException">The extension is not present.</exception>
        public void ReplaceExtension(DerObjectIdentifier oid, bool critical, byte[] extValue) =>
            ReplaceExtension(oid, new X509Extension(critical, DerOctetString.FromContents(extValue)));

        /// <summary>Replace an extension that is already present.</summary>
        /// <param name="oid">The extension type.</param>
        /// <param name="x509Extension">The new extension.</param>
        /// <exception cref="InvalidOperationException">The extension is not present.</exception>
        public void ReplaceExtension(DerObjectIdentifier oid, X509Extension x509Extension)
        {
            if (!HasExtension(oid))
                throw new InvalidOperationException("extension " + oid + " not present");

            m_extensions[oid] = x509Extension;
        }

        /// <summary>Replace an extension that is already present.</summary>
        /// <param name="extension">The new extension.</param>
        /// <exception cref="InvalidOperationException">The extension is not present.</exception>
        public void ReplaceExtension(Extension extension) =>
            ReplaceExtension(extension.ExtnID, extension.GetX509Extension());

        /// <summary>Reset the generator</summary>
        public void Reset()
        {
            m_extensions = new Dictionary<DerObjectIdentifier, X509Extension>();
            m_ordering = new List<DerObjectIdentifier>();
        }

        private void ImplAddExtension(DerObjectIdentifier oid, X509Extension x509Extension)
        {
            m_ordering.Add(oid);
            m_extensions.Add(oid, x509Extension);
        }

        private void ImplAddExtensionDup(X509Extension existingExtension, DerObjectIdentifier oid, bool critical,
            byte[] extValue)
        {
            if (!m_dupsAllowed.Contains(oid))
                throw new ArgumentException("extension " + oid + " already added");

            Asn1Sequence seq1 = Asn1Sequence.GetInstance(existingExtension.Value.GetOctets());
            Asn1Sequence seq2 = Asn1Sequence.GetInstance(extValue);

            var concat = DerSequence.Concatenate(seq1, seq2);

            m_extensions[oid] = new X509Extension(
                existingExtension.IsCritical | critical,
                new DerOctetString(concat));
        }
    }
}
