using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Utilities;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.X509
{
    /// <remarks>
    /// The following extensions are listed in RFC 2459 as relevant to CRL Entries:
    /// <list type="bullet">
    /// <item>Reason Code</item>
    /// <item>Hold Instruction Code</item>
    /// <item>Invalidity Date</item>
    /// <item>Certificate Issuer (critical)</item>
    /// </list>
    /// </remarks>
    public class X509CrlEntry
        : X509ExtensionBase
    {
        private readonly CrlEntry m_crlEntry;
        private readonly X509Name m_certificateIssuer;

        private volatile bool m_hashValueSet;
        private volatile int m_hashValue;

        /// <summary>Create an entry for a CRL that is not an indirect CRL.</summary>
        /// <param name="c">The ASN.1 <see cref="CrlEntry"/> object.</param>
        public X509CrlEntry(CrlEntry c)
        {
            m_crlEntry = c ?? throw new ArgumentNullException(nameof(c));
            m_certificateIssuer = null;
        }

        /// <summary>
        /// Constructor for CRLEntries of indirect CRLs.
        /// </summary>
        /// <remarks>
        /// If <paramref name="isIndirect"/> is <c>false</c> <see cref="GetCertificateIssuer"/> will always return
        /// <c>null</c>, <paramref name="previousCertificateIssuer"/> is ignored. If <c>true</c> and this CRL entry
        /// has no Certificate Issuer extension, then <paramref name="previousCertificateIssuer"/> is returned by
        /// <see cref="GetCertificateIssuer"/>.
        /// </remarks>
        /// <param name="c">The ASN.1 <see cref="CrlEntry"/> object.</param>
        /// <param name="isIndirect"><c>true</c> if the corresponding CRL is an indirect CRL.</param>
        /// <param name="previousCertificateIssuer">Certificate issuer of the previous CRL entry.</param>
        // TODO[api] Rename to 'crlEntry'
        public X509CrlEntry(CrlEntry c, bool isIndirect, X509Name previousCertificateIssuer)
        {
            m_crlEntry = c ?? throw new ArgumentNullException(nameof(c));
            m_certificateIssuer = LoadCertificateIssuer(c, isIndirect, previousCertificateIssuer);
        }

        /// <summary>
        /// Constructor for a CRLEntry whose certificate issuer the caller has already worked out with
        /// <see cref="LoadCertificateIssuer(CrlEntry, bool, X509Name)"/>, which it has to do anyway to track the issuer
        /// from one entry to the next.
        /// </summary>
        internal X509CrlEntry(CrlEntry crlEntry, X509Name certificateIssuer)
        {
            m_crlEntry = crlEntry ?? throw new ArgumentNullException(nameof(crlEntry));
            m_certificateIssuer = certificateIssuer;
        }

        /// <summary>Gets the underlying ASN.1 structure.</summary>
        public virtual CrlEntry CrlEntry => m_crlEntry;

        internal static X509Name LoadCertificateIssuer(CrlEntry c, bool isIndirect, X509Name previousCertificateIssuer)
        {
            if (!isIndirect)
                return null;

            try
            {
                var certificateIssuer = c.Extensions.GetExtension(X509Extensions.CertificateIssuer,
                    GeneralNames.GetInstance);
                if (certificateIssuer == null)
                    return previousCertificateIssuer;

                foreach (var name in certificateIssuer.GetNames())
                {
                    if (name.TagNo == GeneralName.DirectoryName)
                        return X509Name.GetInstance(name.Name);
                }
            }
            catch (Exception)
            {
            }

            return null;
        }

        /// <summary>Return the issuer of the revoked certificate.</summary>
        /// <returns>
        /// The issuer name, or null if the CRL is not an indirect CRL or no issuer can be determined.
        /// </returns>
        public X509Name GetCertificateIssuer() => m_certificateIssuer;

        /// <summary>Returns the extensions of the entry, or null if there are none.</summary>
        protected override X509Extensions GetX509Extensions() => m_crlEntry.Extensions;

        /// <summary>Return the DER encoding of the entry.</summary>
        /// <exception cref="CrlException">The entry could not be encoded.</exception>
        public byte[] GetEncoded()
        {
            try
            {
                return m_crlEntry.GetEncoded(Asn1Encodable.Der);
            }
            catch (IOException e)
            {
                throw new CrlException("Encoding error", e);
            }
        }

        /// <summary>Gets the serial number of the revoked certificate.</summary>
        public BigInteger SerialNumber => m_crlEntry.UserCertificate.Value;

        /// <summary>Gets the date on which the certificate was revoked.</summary>
        public DateTime RevocationDate => m_crlEntry.RevocationDate.ToDateTime();

        /// <summary>Gets whether the entry has any extensions.</summary>
        public bool HasExtensions => m_crlEntry.Extensions != null;

        /// <summary>Two entries are equal if their underlying ASN.1 structures are equal.</summary>
        public override bool Equals(object other)
        {
            if (this == other)
                return true;

            if (!(other is X509CrlEntry that))
                return false;

            if (this.m_hashValueSet && that.m_hashValueSet)
            {
                if (this.m_hashValue != that.m_hashValue)
                    return false;
            }

            // an entry of an indirect CRL applies to the issuer named by its own or a preceding
            // entry's certificateIssuer extension (RFC 5280 sec. 5.3.3), so two entries with the
            // same encoding under different issuers are different entries.
            return this.m_crlEntry.Equals(that.m_crlEntry)
                && Objects.Equals(this.m_certificateIssuer, that.m_certificateIssuer);
        }

        /// <summary>Returns a hash code derived from the underlying ASN.1 structure.</summary>
        public override int GetHashCode()
        {
            if (!m_hashValueSet)
            {
                m_hashValue = m_crlEntry.GetHashCode();
                m_hashValueSet = true;
            }

            return m_hashValue;
        }

        /// <summary>Returns a textual description of the entry.</summary>
        public override string ToString()
        {
            StringBuilder buf = new StringBuilder();

            buf.Append("        userCertificate: ").Append(SerialNumber).AppendLine();
            buf.Append("         revocationDate: ").Append(RevocationDate).AppendLine();
            buf.Append("      certificateIssuer: ").Append(GetCertificateIssuer()).AppendLine();

            X509Extensions extensions = m_crlEntry.Extensions;

            if (extensions != null)
            {
                var e = extensions.ExtensionOids.GetEnumerator();
                if (e.MoveNext())
                {
                    buf.AppendLine("   crlEntryExtensions:");

                    do
                    {
                        DerObjectIdentifier oid = e.Current;
                        X509Extension ext = extensions.GetExtension(oid);

                        if (ext.Value != null)
                        {
                            Asn1Object obj = X509ExtensionUtilities.FromExtensionValue(ext.Value);

                            buf.Append("                       critical(")
                                .Append(ext.IsCritical)
                                .Append(") ");
                            try
                            {
                                if (oid.Equals(X509Extensions.ReasonCode))
                                {
                                    buf.Append(new CrlReason(DerEnumerated.GetInstance(obj)));
                                }
                                else if (oid.Equals(X509Extensions.CertificateIssuer))
                                {
                                    buf.Append("Certificate issuer: ").Append(
                                        GeneralNames.GetInstance((Asn1Sequence)obj));
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
            }

            return buf.ToString();
        }
    }
}
