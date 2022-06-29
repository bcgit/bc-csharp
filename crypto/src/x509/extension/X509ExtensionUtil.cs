using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security.Certificates;

namespace Org.BouncyCastle.X509.Extension
{
	public class X509ExtensionUtilities
	{
		public static Asn1Object FromExtensionValue(
			Asn1OctetString extensionValue)
		{
			return Asn1Object.FromByteArray(extensionValue.GetOctets());
		}

		public static IList<IList<object>> GetIssuerAlternativeNames(X509Certificate cert)
		{
			Asn1OctetString extVal = cert.GetExtensionValue(X509Extensions.IssuerAlternativeName);

			return GetAlternativeName(extVal);
		}

		public static IList<IList<object>> GetSubjectAlternativeNames(X509Certificate cert)
		{
			Asn1OctetString extVal = cert.GetExtensionValue(X509Extensions.SubjectAlternativeName);

			return GetAlternativeName(extVal);
		}

		private static IList<IList<object>> GetAlternativeName(
			Asn1OctetString extVal)
		{
			var result = new List<IList<object>>();

			if (extVal != null)
			{
				try
				{
					Asn1Sequence seq = Asn1Sequence.GetInstance(FromExtensionValue(extVal));

					foreach (Asn1Encodable primName in seq)
					{
						GeneralName genName = GeneralName.GetInstance(primName);

						var list = new List<object>(2);
						list.Add(genName.TagNo);

						switch (genName.TagNo)
						{
						case GeneralName.EdiPartyName:
						case GeneralName.X400Address:
						case GeneralName.OtherName:
							list.Add(genName.Name.ToAsn1Object());
							break;
						case GeneralName.DirectoryName:
							list.Add(X509Name.GetInstance(genName.Name).ToString());
							break;
						case GeneralName.DnsName:
						case GeneralName.Rfc822Name:
						case GeneralName.UniformResourceIdentifier:
							list.Add(((IAsn1String)genName.Name).GetString());
							break;
						case GeneralName.RegisteredID:
							list.Add(DerObjectIdentifier.GetInstance(genName.Name).Id);
							break;
						case GeneralName.IPAddress:
							list.Add(Asn1OctetString.GetInstance(genName.Name).GetOctets());
							break;
						default:
							throw new IOException("Bad tag number: " + genName.TagNo);
						}

						result.Add(list);
					}
				}
				catch (Exception e)
				{
					throw new CertificateParsingException(e.Message);
				}
			}

			return result;
		}
	}
}
