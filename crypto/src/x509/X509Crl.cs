using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Utilities;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.X509
{
    /// <remarks>
    /// The following extensions are listed in RFC 2459 as relevant to CRLs:
    /// <list type="bullet">
    /// <item>Authority Key Identifier</item>
    /// <item>Issuer Alternative Name</item>
    /// <item>CRL Number</item>
    /// <item>Delta CRL Indicator (critical)</item>
    /// <item>Issuing Distribution Point (critical)</item>
    /// </list>
    /// </remarks>
    public class X509Crl
        : X509ExtensionBase
    {
        private class CachedEncoding
        {
            private readonly byte[] m_encoding;
            private readonly CrlException m_exception;

            internal CachedEncoding(byte[] encoding, CrlException exception)
            {
                m_encoding = encoding;
                m_exception = exception;
            }

            internal byte[] Encoding => m_encoding;

            internal byte[] GetEncoded()
            {
                if (null != m_exception)
                    throw m_exception;

                if (null == m_encoding)
                    throw new CrlException();

                return m_encoding;
            }
        }

        private readonly CertificateList m_certificateList;
        private readonly byte[] m_sigAlgParams;
        private readonly bool m_isIndirect;

        private string m_sigAlgName = null;

        private CachedEncoding m_cachedEncoding;

        private volatile bool m_hashValueSet;
        private volatile int m_hashValue;

        /// <summary>Parse a CRL from its encoding.</summary>
        /// <param name="encoding">The encoded CRL.</param>
        public X509Crl(byte[] encoding)
            : this(CertificateList.GetInstance(encoding))
        {
        }

        /// <summary>Wrap an ASN.1 CertificateList structure.</summary>
        /// <param name="c">The ASN.1 structure.</param>
        /// <exception cref="CrlException">The contents of the CRL are invalid.</exception>
        public X509Crl(CertificateList c)
        {
            m_certificateList = c ?? throw new ArgumentNullException(nameof(c));

            try
            {
                Asn1Encodable parameters = c.SignatureAlgorithm.Parameters;
                m_sigAlgParams = parameters?.GetEncoded(Asn1Encodable.Der);

                m_isIndirect = ImplIsIndirectCrl(c);
            }
            catch (Exception e)
            {
                throw new CrlException("CRL contents invalid", e);
            }
        }

        /// <summary>Gets the underlying ASN.1 structure.</summary>
        public virtual CertificateList CertificateList => m_certificateList;

        /// <summary>Returns the extensions of the CRL, or null for a version 1 CRL.</summary>
        protected override X509Extensions GetX509Extensions() =>
            m_certificateList.Version >= 2 ? m_certificateList.Extensions : null;

        // TODO[api] Rename 'key' to 'publicKey'
        /// <summary>Check whether the CRL signature is valid for the given public key.</summary>
        /// <param name="key">The public key of the issuer.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        /// <exception cref="CrlException">The signature algorithms in the CRL do not match.</exception>
        public virtual bool IsSignatureValid(AsymmetricKeyParameter key) =>
            CheckSignatureValid(new Asn1VerifierFactory(m_certificateList.SignatureAlgorithm, key));

        /// <summary>Check whether the CRL signature is valid, using a verifier from the given provider.</summary>
        /// <param name="verifierProvider">A provider of signature verifier factories.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        /// <exception cref="CrlException">The signature algorithms in the CRL do not match.</exception>
        public virtual bool IsSignatureValid(IVerifierFactoryProvider verifierProvider) =>
            CheckSignatureValid(verifierProvider.CreateVerifierFactory(m_certificateList.SignatureAlgorithm));

        /// <summary>Check whether the alternative signature carried in the CRL's extensions is valid.</summary>
        /// <param name="verifierProvider">A provider of signature verifier factories.</param>
        /// <returns>true if the alternative signature is valid, false otherwise.</returns>
        public virtual bool IsAlternativeSignatureValid(IVerifierFactoryProvider verifierProvider)
        {
            var tbsCertList = m_certificateList.TbsCertList;
            var extensions = tbsCertList.Extensions;

            AltSignatureAlgorithm altSigAlg = AltSignatureAlgorithm.FromExtensions(extensions);
            AltSignatureValue altSigValue = AltSignatureValue.FromExtensions(extensions);

            var verifier = verifierProvider.CreateVerifierFactory(altSigAlg.Algorithm);

            Asn1Sequence tbsSeq = Asn1Sequence.GetInstance(tbsCertList.ToAsn1Object());
            Asn1EncodableVector v = new Asn1EncodableVector();

            int start = 1;    //  want to skip signature field
            if (tbsSeq[0] is DerInteger version)
            {
                v.Add(version);
                start++;
            }

            for (int i = start; i < tbsSeq.Count - 1; i++)
            {
                v.Add(tbsSeq[i]);
            }

            v.Add(new DerTaggedObject(true, 0, extensions.ToAsn1ObjectTrimmed()));

            return X509Utilities.VerifySignature(verifier, new DerSequence(v), altSigValue.Signature);
        }

        /// <summary>Verify the CRL signature with the given public key.</summary>
        /// <param name="publicKey">The public key of the issuer.</param>
        /// <exception cref="InvalidKeyException">The CRL does not verify with the key.</exception>
        /// <exception cref="CrlException">The signature algorithms in the CRL do not match.</exception>
        public virtual void Verify(AsymmetricKeyParameter publicKey) =>
            CheckSignature(new Asn1VerifierFactory(m_certificateList.SignatureAlgorithm, publicKey));

        /// <summary>Verify the CRL signature, using a verifier from the given provider.</summary>
        /// <param name="verifierProvider">A provider of signature verifier factories.</param>
        /// <exception cref="InvalidKeyException">The CRL does not verify.</exception>
        /// <exception cref="CrlException">The signature algorithms in the CRL do not match.</exception>
        public virtual void Verify(IVerifierFactoryProvider verifierProvider) =>
            CheckSignature(verifierProvider.CreateVerifierFactory(m_certificateList.SignatureAlgorithm));

        /// <summary>Verify the alternative signature carried in the CRL's extensions.</summary>
        /// <param name="verifierProvider">A provider of signature verifier factories.</param>
        /// <exception cref="InvalidKeyException">The alternative signature does not verify.</exception>
        public virtual void VerifyAltSignature(IVerifierFactoryProvider verifierProvider)
        {
            if (!IsAlternativeSignatureValid(verifierProvider))
                throw new InvalidKeyException("CRL alternative signature does not verify with supplied public key.");
        }

        /// <summary>Verify the CRL signature using the given verifier factory.</summary>
        /// <param name="verifier">The verifier factory.</param>
        /// <exception cref="InvalidKeyException">The CRL does not verify.</exception>
        protected virtual void CheckSignature(IVerifierFactory verifier)
        {
            if (!CheckSignatureValid(verifier))
                throw new InvalidKeyException("CRL does not verify with supplied public key.");
        }

        /// <summary>Check the CRL signature using the given verifier factory.</summary>
        /// <param name="verifier">The verifier factory.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        /// <exception cref="CrlException">The signature algorithms in the CRL do not match.</exception>
        protected virtual bool CheckSignatureValid(IVerifierFactory verifier)
        {
            var tbsCertList = m_certificateList.TbsCertList;

            if (!X509Utilities.AreEquivalentAlgorithms(m_certificateList.SignatureAlgorithm, tbsCertList.Signature))
                throw new CrlException("Signature algorithm on CertificateList does not match TbsCertList.");

            return X509Utilities.VerifySignature(verifier, tbsCertList, m_certificateList.Signature);
        }

        /// <summary>Gets the version number of the CRL (1 or 2).</summary>
        public virtual int Version => m_certificateList.Version;

        /// <summary>Gets the distinguished name of the CRL issuer.</summary>
        public virtual X509Name IssuerDN => m_certificateList.Issuer;

        /// <summary>Gets the date this CRL was issued.</summary>
        public virtual DateTime ThisUpdate => m_certificateList.ThisUpdate.ToDateTime();

        /// <summary>Gets the date by which the next CRL will be issued, or null if not specified.</summary>
        public virtual DateTime? NextUpdate => m_certificateList.NextUpdate?.ToDateTime();

        /// <summary>
        /// Returns the first entry with the serial number whatever its issuer - the cert path validators rely on that.
        /// </summary>
        public virtual X509CrlEntry GetRevokedCertificate(BigInteger serialNumber)
        {
            X509Name certificateIssuer = null;
            foreach (CrlEntry entry in m_certificateList.GetRevokedCertificateEnumeration())
            {
                certificateIssuer = X509CrlEntry.LoadCertificateIssuer(entry, m_isIndirect, certificateIssuer);

                if (entry.UserCertificate.HasValue(serialNumber))
                    return new X509CrlEntry(entry, certificateIssuer);
            }

            return null;
        }

        /// <summary>
        /// Return the entry for the given certificate, matching its issuer as well as its serial number:
        /// an indirect CRL (RFC 5280 sec. 5.2.5) lists certificates from more than one issuer and a serial
        /// number is only unique within its issuer, so the entry cannot be located by serial number alone.
        /// </summary>
        public virtual X509CrlEntry GetRevokedCertificate(X509Certificate certificate)
        {
            var entries = m_certificateList.GetRevokedCertificateEnumeration().GetEnumerator();
            if (entries.MoveNext())
            {
                var certIssuer = certificate.IssuerDN;
                var certSerial = certificate.SerialNumber;

                bool certIssuedByCrlIssuer = certIssuer.Equivalent(IssuerDN, true);

                if (!m_isIndirect)
                    return certIssuedByCrlIssuer ? GetRevokedCertificate(certSerial) : null;

                X509Name certificateIssuer = null;
                do
                {
                    var entry = entries.Current;

                    certificateIssuer = X509CrlEntry.LoadCertificateIssuer(entry, m_isIndirect, certificateIssuer);

                    // a serial number is only unique within its issuer, so another issuer's entry is not this one.
                    if (entry.UserCertificate.HasValue(certSerial))
                    {
                        bool certIssuerMatches = certIssuedByCrlIssuer;
                        if (certificateIssuer != null)
                        {
                            certIssuerMatches = certIssuer.Equivalent(certificateIssuer, true);
                        }

                        if (certIssuerMatches)
                            return new X509CrlEntry(entry, certificateIssuer);
                    }
                }
                while (entries.MoveNext());
            }

            return null;
        }

        /// <summary>Return the entries of all the revoked certificates listed in the CRL.</summary>
        /// <returns>The entries, or null if there are none.</returns>
        public virtual ISet<X509CrlEntry> GetRevokedCertificates()
        {
            var entries = m_certificateList.GetRevokedCertificateEnumeration().GetEnumerator();
            if (!entries.MoveNext())
                return null;

            var entrySet = new HashSet<X509CrlEntry>();
            X509Name certificateIssuer = null;
            do
            {
                var entry = entries.Current;
                certificateIssuer = X509CrlEntry.LoadCertificateIssuer(entry, m_isIndirect, certificateIssuer);
                entrySet.Add(new X509CrlEntry(entry, certificateIssuer));
            }
            while (entries.MoveNext());

            return entrySet;
        }

        /// <summary>Return the DER encoding of the tbsCertList field.</summary>
        /// <exception cref="CrlException">The field could not be encoded.</exception>
        public virtual byte[] GetTbsCertList()
        {
            try
            {
                return m_certificateList.TbsCertList.GetDerEncoded();
            }
            catch (IOException e)
            {
                throw new CrlException("Encoding error", e);
            }
        }

        /// <summary>Return the signature octets.</summary>
        public virtual byte[] GetSignature() => m_certificateList.GetSignatureOctets();

        /// <summary>
        /// A meaningful version of the Signature Algorithm. (e.g. SHA1WITHRSA)
        /// </summary>
        /// <returns>A string representing the signature algorithm.</returns>
        public virtual string SigAlgName => Objects.EnsureSingletonInitialized(ref m_sigAlgName, SignatureAlgorithm,
            X509SignatureUtilities.GetSignatureName);

        /// <summary>Gets the object identifier of the signature algorithm.</summary>
        public virtual string SigAlgOid => m_certificateList.SignatureAlgorithm.Algorithm.GetID();

        /// <summary>Return a copy of the DER encoding of the signature algorithm parameters, or null if there are none.
        /// </summary>
        public virtual byte[] GetSigAlgParams() => Arrays.Clone(m_sigAlgParams);

        /// <summary>Gets the signature algorithm identifier.</summary>
        public virtual AlgorithmIdentifier SignatureAlgorithm => m_certificateList.SignatureAlgorithm;

        /// <summary>
        /// Return the DER encoding of this CRL.
        /// </summary>
        /// <returns>A byte array containing the DER encoding of this CRL.</returns>
        /// <exception cref="CrlException">If there is an error encoding the CRL.</exception>
        public virtual byte[] GetEncoded() => Arrays.Clone(GetCachedEncoding().GetEncoded());

        /// <summary>Two CRLs are equal if their DER encodings are equal.</summary>
        public override bool Equals(object other)
        {
            if (this == other)
                return true;

            if (!(other is X509Crl that))
                return false;

            if (this.m_hashValueSet && that.m_hashValueSet)
            {
                if (this.m_hashValue != that.m_hashValue)
                    return false;
            }
            else if (null == this.m_cachedEncoding || null == that.m_cachedEncoding)
            {
                DerBitString signature = m_certificateList.Signature;
                if (null != signature && !signature.Equals(that.m_certificateList.Signature))
                    return false;
            }

            byte[] thisEncoding = this.GetCachedEncoding().Encoding;
            byte[] thatEncoding = that.GetCachedEncoding().Encoding;

            return null != thisEncoding
                && null != thatEncoding
                && Arrays.AreEqual(thisEncoding, thatEncoding);
        }

        /// <summary>Returns a hash code derived from the DER encoding.</summary>
        public override int GetHashCode()
        {
            if (!m_hashValueSet)
            {
                byte[] thisEncoding = this.GetCachedEncoding().Encoding;

                m_hashValue = Arrays.GetHashCode(thisEncoding);
                m_hashValueSet = true;
            }

            return m_hashValue;
        }

        /// <summary>Returns a string representation of this CRL.</summary>
        public override string ToString()
        {
            StringBuilder buf = new StringBuilder();

            buf.Append("              Version: ").Append(Version).AppendLine();
            buf.Append("             IssuerDN: ").Append(IssuerDN).AppendLine();
            buf.Append("          This update: ").Append(ThisUpdate).AppendLine();
            buf.Append("          Next update: ").Append(NextUpdate).AppendLine();
            buf.Append("  Signature Algorithm: ").Append(SigAlgName).AppendLine();

            byte[] sig = GetSignature();
            int sigPos = System.Math.Min(20, sig.Length);

            buf.Append("            Signature: ").AppendLine(Hex.ToHexString(sig, 0, sigPos));

            while (sigPos < sig.Length)
            {
                int next = System.Math.Min(20, sig.Length - sigPos);
                buf.Append("                       ").AppendLine(Hex.ToHexString(sig, sigPos, next));
                sigPos += next;
            }

            X509Extensions extensions = m_certificateList.TbsCertList.Extensions;

            if (extensions != null)
            {
                var e = extensions.ExtensionOids.GetEnumerator();

                if (e.MoveNext())
                {
                    buf.AppendLine("           Extensions:");
                }

                do
                {
                    DerObjectIdentifier oid = e.Current;
                    X509Extension ext = extensions.GetExtension(oid);

                    if (ext.Value != null)
                    {
                        Asn1Object obj = X509ExtensionUtilities.FromExtensionValue(ext.Value);

                        buf.Append("                       critical(").Append(ext.IsCritical).Append(") ");
                        try
                        {
                            if (oid.Equals(X509Extensions.CrlNumber))
                            {
                                buf.Append(new CrlNumber(DerInteger.GetInstance(obj).PositiveValue));
                            }
                            else if (oid.Equals(X509Extensions.DeltaCrlIndicator))
                            {
                                buf.Append(
                                    "Base CRL: "
                                    + new CrlNumber(DerInteger.GetInstance(
                                    obj).PositiveValue));
                            }
                            else if (oid.Equals(X509Extensions.IssuingDistributionPoint))
                            {
                                buf.Append(IssuingDistributionPoint.GetInstance((Asn1Sequence)obj));
                            }
                            else if (oid.Equals(X509Extensions.CrlDistributionPoints))
                            {
                                buf.Append(CrlDistPoint.GetInstance((Asn1Sequence)obj));
                            }
                            else if (oid.Equals(X509Extensions.FreshestCrl))
                            {
                                buf.Append(CrlDistPoint.GetInstance((Asn1Sequence)obj));
                            }
                            else
                            {
                                buf.Append(oid.GetID());
                                buf.Append(" value = ");
                                Asn1Dump.AppendAsString(buf, obj);
                            }
                        }
                        catch (Exception)
                        {
                            buf.Append(oid.GetID());
                            buf.Append(" value = ").Append("*****");
                        }
                    }

                    buf.AppendLine();
                }
                while (e.MoveNext());
            }

            var certSet = GetRevokedCertificates();
            if (certSet != null)
            {
                foreach (X509CrlEntry entry in certSet)
                {
                    buf.Append(entry);
                    buf.AppendLine();
                }
            }

            return buf.ToString();
        }

        /// <summary>Checks whether the given certificate is on this CRL.</summary>
        /// <param name="cert">The certificate to check for.</param>
        /// <returns><c>true</c> if the given certificate is on this CRL, <c>false</c> otherwise.</returns>
        public virtual bool IsRevoked(X509Certificate cert) => GetRevokedCertificate(cert) != null;

        public virtual bool IsIndirect => m_isIndirect;

        /// <summary>
        /// Gets whether this is an indirect CRL, according to its issuing distribution point extension.
        /// </summary>
        /// <exception cref="CrlException">The extension could not be read.</exception>
        [Obsolete("Use 'IsIndirect' instead")]
        protected virtual bool IsIndirectCrl => m_isIndirect;

        internal byte[] GetEncodedInternal() => GetCachedEncoding().GetEncoded();

        private CachedEncoding GetCachedEncoding() =>
            Objects.EnsureSingletonInitialized(ref m_cachedEncoding, m_certificateList, CreateCachedEncoding);

        private static CachedEncoding CreateCachedEncoding(CertificateList c)
        {
            byte[] encoding = null;
            CrlException exception = null;
            try
            {
                encoding = c.GetEncoded(Asn1Encodable.Der);
            }
            catch (IOException e)
            {
                exception = new CrlException("Failed to DER-encode CRL", e);
            }

            return new CachedEncoding(encoding, exception);
        }

        private static bool ImplIsIndirectCrl(CertificateList certificateList)
        {
            try
            {
                var idp = certificateList.Extensions.GetExtension(X509Extensions.IssuingDistributionPoint,
                    IssuingDistributionPoint.GetInstance);
                return idp != null && idp.IsIndirectCrl;
            }
            catch (Exception e)
            {
                throw new CrlException("Exception reading IssuingDistributionPoint", e);
            }
        }
    }
}
