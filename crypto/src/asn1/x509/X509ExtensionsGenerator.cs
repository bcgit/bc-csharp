using System;
using System.Collections;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <remarks>Generator for X.509 extensions</remarks>
    public class X509ExtensionsGenerator
    {
        private IDictionary extensions = Platform.CreateHashtable();
        private IList extOrdering = Platform.CreateArrayList();

        private static readonly IDictionary dupsAllowed = Platform.CreateHashtable();

        static X509ExtensionsGenerator()
        {
            dupsAllowed.Add(X509Extensions.SubjectAlternativeName, true);
            dupsAllowed.Add(X509Extensions.IssuerAlternativeName, true);
            dupsAllowed.Add(X509Extensions.SubjectDirectoryAttributes, true);
            dupsAllowed.Add(X509Extensions.CertificateIssuer, true);

        }



        /// <summary>Reset the generator</summary>
        public void Reset()
        {
            extensions = Platform.CreateHashtable();
            extOrdering = Platform.CreateArrayList();
        }

        /// <summary>
        /// Add an extension with the given oid and the passed in value to be included
        /// in the OCTET STRING associated with the extension.
        /// </summary>
        /// <param name="oid">OID for the extension.</param>
        /// <param name="critical">True if critical, false otherwise.</param>
        /// <param name="extValue">The ASN.1 object to be included in the extension.</param>
        public void AddExtension(
            DerObjectIdentifier oid,
            bool critical,
            Asn1Encodable extValue)
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
        public void AddExtension(
            DerObjectIdentifier oid,
            bool critical,
            byte[] extValue)
        {
            if (extensions.Contains(oid))
            {
                if (dupsAllowed.Contains(oid))
                {
                    X509Extension existingExtension = (X509Extension)extensions[oid];

                    Asn1Sequence seq1 = Asn1Sequence.GetInstance(DerOctetString.GetInstance(existingExtension.Value).GetOctets());
                    Asn1EncodableVector items = Asn1EncodableVector.FromEnumerable(seq1);
                    Asn1Sequence seq2 = Asn1Sequence.GetInstance(extValue);

                    foreach (Asn1Encodable enc in seq2)
                    {
                        items.Add(enc);
                    }

                    extensions[oid] = new X509Extension(existingExtension.IsCritical, new DerOctetString(new DerSequence(items).GetEncoded()));

                }
                else
                {
                    throw new ArgumentException("extension " + oid + " already added");
                }
            }
            else
            {
                extOrdering.Add(oid);
                extensions.Add(oid, new X509Extension(critical, new DerOctetString(extValue)));
            }
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
            get { return extOrdering.Count < 1; }
        }

        /// <summary>Generate an X509Extensions object based on the current state of the generator.</summary>
        /// <returns>An <c>X509Extensions</c> object</returns>
        public X509Extensions Generate()
        {
            return new X509Extensions(extOrdering, extensions);
        }

        internal void AddExtension(DerObjectIdentifier oid, X509Extension x509Extension)
        {
            if (extensions.Contains(oid))
            {
                throw new ArgumentException("extension " + oid + " already added");
            }

            extOrdering.Add(oid);
            extensions.Add(oid, x509Extension);
        }
    }
}
