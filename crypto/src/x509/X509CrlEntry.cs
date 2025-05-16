using System;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Utilities;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.X509
{
	/**
	 * The following extensions are listed in RFC 2459 as relevant to CRL Entries
	 *
	 * ReasonCode Hode Instruction Code Invalidity Date Certificate Issuer
	 * (critical)
	 */
	public class X509CrlEntry
		: X509ExtensionBase
	{
		private CrlEntry	c;
		private bool		isIndirect;
		private X509Name	previousCertificateIssuer;
		private X509Name	certificateIssuer;

        private volatile bool hashValueSet;
        private volatile int hashValue;

		public X509CrlEntry(CrlEntry c)
		{
			this.c = c;
			this.certificateIssuer = LoadCertificateIssuer();
		}

		/**
		* Constructor for CRLEntries of indirect CRLs. If <code>isIndirect</code>
		* is <code>false</code> {@link #getCertificateIssuer()} will always
		* return <code>null</code>, <code>previousCertificateIssuer</code> is
		* ignored. If this <code>isIndirect</code> is specified and this CrlEntry
		* has no certificate issuer CRL entry extension
		* <code>previousCertificateIssuer</code> is returned by
		* {@link #getCertificateIssuer()}.
		*
		* @param c
		*            TbsCertificateList.CrlEntry object.
		* @param isIndirect
		*            <code>true</code> if the corresponding CRL is a indirect
		*            CRL.
		* @param previousCertificateIssuer
		*            Certificate issuer of the previous CrlEntry.
		*/
		public X509CrlEntry(CrlEntry c, bool isIndirect, X509Name previousCertificateIssuer)
		{
			this.c = c;
			this.isIndirect = isIndirect;
			this.previousCertificateIssuer = previousCertificateIssuer;
			this.certificateIssuer = LoadCertificateIssuer();
		}

		public virtual CrlEntry CrlEntry => c;

		private X509Name LoadCertificateIssuer()
		{
			if (!isIndirect)
				return null;

			var certificateIssuer = this.GetExtension(X509Extensions.CertificateIssuer, GeneralNames.GetInstance);
			if (certificateIssuer == null)
				return previousCertificateIssuer;

			try
			{
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

		public X509Name GetCertificateIssuer() => certificateIssuer;

		protected override X509Extensions GetX509Extensions() => c.Extensions;

		public byte[] GetEncoded()
		{
			try
			{
				return c.GetEncoded(Asn1Encodable.Der);
			}
			catch (Exception e)
			{
				throw new CrlException(e.ToString());
			}
		}

		public BigInteger SerialNumber => c.UserCertificate.Value;

		public DateTime RevocationDate => c.RevocationDate.ToDateTime();

		public bool HasExtensions => c.Extensions != null;

        public override bool Equals(object other)
        {
            if (this == other)
                return true;

            if (!(other is X509CrlEntry that))
                return false;

            if (this.hashValueSet && that.hashValueSet)
            {
                if (this.hashValue != that.hashValue)
                    return false;
            }

            return this.c.Equals(that.c);
        }

        public override int GetHashCode()
        {
            if (!hashValueSet)
            {
                hashValue = this.c.GetHashCode();
                hashValueSet = true;
            }

            return hashValue;
        }

		public override string ToString()
		{
			StringBuilder buf = new StringBuilder();

			buf.Append("        userCertificate: ").Append(this.SerialNumber).AppendLine();
			buf.Append("         revocationDate: ").Append(this.RevocationDate).AppendLine();
			buf.Append("      certificateIssuer: ").Append(this.GetCertificateIssuer()).AppendLine();

			X509Extensions extensions = c.Extensions;

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
									buf.Append(oid.Id);
									buf.Append(" value = ").Append(Asn1Dump.DumpAsString(obj));
								}
								buf.AppendLine();
							}
							catch (Exception)
							{
								buf.Append(oid.Id);
								buf.Append(" value = ").Append("*****").AppendLine();
							}
						}
						else
						{
							buf.AppendLine();
						}
					}
					while (e.MoveNext());
				}
			}

			return buf.ToString();
		}
	}
}
