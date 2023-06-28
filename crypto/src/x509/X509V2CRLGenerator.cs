using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security.Certificates;

namespace Org.BouncyCastle.X509
{
	/**
	* class to produce an X.509 Version 2 CRL.
	*/
	public class X509V2CrlGenerator
	{
		private readonly X509ExtensionsGenerator extGenerator = new X509ExtensionsGenerator();

		private V2TbsCertListGenerator tbsGen;

		public X509V2CrlGenerator()
		{
			tbsGen = new V2TbsCertListGenerator();
		}

        /// <summary>Create a builder for a version 2 CRL, initialised with another CRL.</summary>
		/// <param name="template">Template CRL to base the new one on.</param>
        public X509V2CrlGenerator(X509Crl template)
			: this(template.CertificateList)
		{
		}

        public X509V2CrlGenerator(CertificateList template)
        {
            tbsGen = new V2TbsCertListGenerator();
            tbsGen.SetIssuer(template.Issuer);
            tbsGen.SetThisUpdate(template.ThisUpdate);
            tbsGen.SetNextUpdate(template.NextUpdate);

            AddCrl(new X509Crl(template));

            var extensions = template.TbsCertList.Extensions;
            if (extensions != null)
            {
				foreach (var oid in extensions.ExtensionOids)
				{
					if (X509Extensions.AltSignatureAlgorithm.Equals(oid) ||
						X509Extensions.AltSignatureValue.Equals(oid))
					{
						continue;
					}

					X509Extension ext = extensions.GetExtension(oid);
					extGenerator.AddExtension(oid, ext.critical, ext.Value.GetOctets());
				}
            }
        }

        /**
		* reset the generator
		*/
		public void Reset()
		{
			tbsGen = new V2TbsCertListGenerator();
			extGenerator.Reset();
		}

		/**
		* Set the issuer distinguished name - the issuer is the entity whose private key is used to sign the
		* certificate.
		*/
		public void SetIssuerDN(
			X509Name issuer)
		{
			tbsGen.SetIssuer(issuer);
		}

		public void SetThisUpdate(
			DateTime date)
		{
			tbsGen.SetThisUpdate(new Time(date));
		}

		public void SetNextUpdate(
			DateTime date)
		{
			tbsGen.SetNextUpdate(new Time(date));
		}

		/**
		* Reason being as indicated by CrlReason, i.e. CrlReason.KeyCompromise
		* or 0 if CrlReason is not to be used
		**/
		public void AddCrlEntry(
			BigInteger	userCertificate,
			DateTime	revocationDate,
			int			reason)
		{
			tbsGen.AddCrlEntry(new DerInteger(userCertificate), new Time(revocationDate), reason);
		}

		/**
		* Add a CRL entry with an Invalidity Date extension as well as a CrlReason extension.
		* Reason being as indicated by CrlReason, i.e. CrlReason.KeyCompromise
		* or 0 if CrlReason is not to be used
		**/
		public void AddCrlEntry(
			BigInteger	userCertificate,
			DateTime	revocationDate,
			int			reason,
			DateTime	invalidityDate)
		{
			tbsGen.AddCrlEntry(new DerInteger(userCertificate), new Time(revocationDate), reason,
				new Asn1GeneralizedTime(invalidityDate));
		}

		/**
		* Add a CRL entry with extensions.
		**/
		public void AddCrlEntry(
			BigInteger		userCertificate,
			DateTime		revocationDate,
			X509Extensions	extensions)
		{
			tbsGen.AddCrlEntry(new DerInteger(userCertificate), new Time(revocationDate), extensions);
		}

		/**
		* Add the CRLEntry objects contained in a previous CRL.
		*
		* @param other the X509Crl to source the other entries from.
		*/
		public void AddCrl(X509Crl other)
		{
			if (other == null)
				throw new ArgumentNullException("other");

			var revocations = other.GetRevokedCertificates();

			if (revocations != null)
			{
				foreach (X509CrlEntry entry in revocations)
				{
					try
					{
						tbsGen.AddCrlEntry(
							Asn1Sequence.GetInstance(
							Asn1Object.FromByteArray(entry.GetEncoded())));
					}
					catch (IOException e)
					{
						throw new CrlException("exception processing encoding of CRL", e);
					}
				}
			}
		}

		/**
		* add a given extension field for the standard extensions tag (tag 0)
		*/
		public void AddExtension(
			string			oid,
			bool			critical,
			Asn1Encodable	extensionValue)
		{
			extGenerator.AddExtension(new DerObjectIdentifier(oid), critical, extensionValue);
		}

		/**
		* add a given extension field for the standard extensions tag (tag 0)
		*/
		public void AddExtension(
			DerObjectIdentifier	oid,
			bool				critical,
			Asn1Encodable		extensionValue)
		{
			extGenerator.AddExtension(oid, critical, extensionValue);
		}

		/**
		* add a given extension field for the standard extensions tag (tag 0)
		*/
		public void AddExtension(
			string	oid,
			bool	critical,
			byte[]	extensionValue)
		{
			extGenerator.AddExtension(new DerObjectIdentifier(oid), critical, new DerOctetString(extensionValue));
		}

		/**
		* add a given extension field for the standard extensions tag (tag 0)
		*/
		public void AddExtension(
			DerObjectIdentifier	oid,
			bool				critical,
			byte[]				extensionValue)
		{
			extGenerator.AddExtension(oid, critical, new DerOctetString(extensionValue));
		}

		/// <summary>
		/// Generate a new <see cref="X509Crl"/> using the provided <see cref="ISignatureFactory"/>.
		/// </summary>
		/// <param name="signatureFactory">A <see cref="ISignatureFactory">signature factory</see> with the necessary
		/// algorithm details.</param>
		/// <returns>An <see cref="X509Crl"/>.</returns>
		public X509Crl Generate(ISignatureFactory signatureFactory)
        {
			var sigAlgID = (AlgorithmIdentifier)signatureFactory.AlgorithmDetails;

			tbsGen.SetSignature(sigAlgID);

			if (!extGenerator.IsEmpty)
			{
				tbsGen.SetExtensions(extGenerator.Generate());
			}

			var tbsCertList = tbsGen.GenerateTbsCertList();

			var signature = X509Utilities.GenerateSignature(signatureFactory, tbsCertList);

			return new X509Crl(CertificateList.GetInstance(new DerSequence(tbsCertList, sigAlgID, signature)));
		}

        /// <summary>
        /// Generate a new <see cref="X509Crl"/> using the provided <see cref="ISignatureFactory"/> and
        /// containing altSignatureAlgorithm and altSignatureValue extensions based on the passed
        /// <paramref name="altSignatureFactory"/>.
        /// </summary>
        /// <param name="signatureFactory">A <see cref="ISignatureFactory">signature factory</see> with the necessary
        /// algorithm details.</param>
        /// <param name="isCritical">Whether the 'alt' extensions should be marked critical.</param>
        /// <param name="altSignatureFactory">A <see cref="ISignatureFactory">signature factory</see> used to create the
        /// altSignatureAlgorithm and altSignatureValue extensions.</param>
        /// <returns>An <see cref="X509Certificate"/>.</returns>
        public X509Crl Generate(ISignatureFactory signatureFactory, bool isCritical,
            ISignatureFactory altSignatureFactory)
		{
            tbsGen.SetSignature(null);

            var altSigAlgID = (AlgorithmIdentifier)altSignatureFactory.AlgorithmDetails;
            extGenerator.AddExtension(X509Extensions.AltSignatureAlgorithm, isCritical, altSigAlgID);

            tbsGen.SetExtensions(extGenerator.Generate());

            var altSignature = X509Utilities.GenerateSignature(altSignatureFactory, tbsGen.GeneratePreTbsCertList());
            extGenerator.AddExtension(X509Extensions.AltSignatureValue, isCritical, altSignature);

            return Generate(signatureFactory);
		}

		/// <summary>
		/// Allows enumeration of the signature names supported by the generator.
		/// </summary>
		public IEnumerable<string> SignatureAlgNames
		{
			get { return X509Utilities.GetAlgNames(); }
		}
	}
}
