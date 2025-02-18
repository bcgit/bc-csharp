using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.IsisMtt;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>
    /// Summary description for PkixCertPathValidatorUtilities.
    /// </summary>
    internal static class PkixCertPathValidatorUtilities
	{
		internal static readonly string ANY_POLICY = "2.5.29.32.0";
		internal static readonly DerObjectIdentifier ANY_POLICY_OID = new DerObjectIdentifier(ANY_POLICY);

        internal static readonly string CRL_NUMBER = X509Extensions.CrlNumber.Id;

		/// <summary>
		/// key usage bits
		/// </summary>
		internal static readonly int KEY_CERT_SIGN = 5;
		internal static readonly int CRL_SIGN = 6;

		//internal static readonly string[] crlReasons = new string[]
		//{
		//	"unspecified",
		//	"keyCompromise",
		//	"cACompromise",
		//	"affiliationChanged",
		//	"superseded",
		//	"cessationOfOperation",
		//	"certificateHold",
		//	"unknown",
		//	"removeFromCRL",
		//	"privilegeWithdrawn",
		//	"aACompromise"
		//};

		/// <summary>
		/// Search the given Set of TrustAnchor's for one that is the
		/// issuer of the given X509 certificate.
		/// </summary>
		/// <param name="cert">the X509 certificate</param>
		/// <param name="trustAnchors">a Set of TrustAnchor's</param>
		/// <returns>the <code>TrustAnchor</code> object if found or
		/// <code>null</code> if not.
		/// </returns>
		/// @exception
		internal static TrustAnchor FindTrustAnchor(X509Certificate	cert, ISet<TrustAnchor> trustAnchors)
		{
			var iter = trustAnchors.GetEnumerator();
			TrustAnchor trust = null;
			AsymmetricKeyParameter trustPublicKey = null;
			Exception invalidKeyEx = null;

			X509CertStoreSelector certSelectX509 = new X509CertStoreSelector();

			try
			{
				certSelectX509.Subject = GetIssuerPrincipal(cert);
			}
			catch (IOException ex)
			{
				throw new Exception("Cannot set subject search criteria for trust anchor.", ex);
			}

			while (iter.MoveNext() && trust == null)
			{
				trust = iter.Current;
				if (trust.TrustedCert != null)
				{
					if (certSelectX509.Match(trust.TrustedCert))
					{
						trustPublicKey = trust.TrustedCert.GetPublicKey();
					}
					else
					{
						trust = null;
					}
				}
				else if (trust.CAName != null && trust.CAPublicKey != null)
				{
					try
					{
						X509Name certIssuer = GetIssuerPrincipal(cert);
						X509Name caName = new X509Name(trust.CAName);

						if (certIssuer.Equivalent(caName, true))
						{
							trustPublicKey = trust.CAPublicKey;
						}
						else
						{
							trust = null;
						}
					}
					catch (InvalidParameterException)
					{
						trust = null;
					}
				}
				else
				{
					trust = null;
				}

				if (trustPublicKey != null)
				{
					try
					{
						cert.Verify(trustPublicKey);
					}
					catch (Exception ex)
					{
						invalidKeyEx = ex;
						trust = null;
					}
				}
			}

			if (trust == null && invalidKeyEx != null)
			{
				throw new Exception("TrustAnchor found but certificate validation failed.", invalidKeyEx);
			}

			return trust;
		}

        internal static bool IsIssuerTrustAnchor(X509Certificate cert, ISet<TrustAnchor> trustAnchors)
        {
            try
            {
                return FindTrustAnchor(cert, trustAnchors) != null;
            }
            catch (Exception)
            {
                return false;
            }
        }

		internal static void AddAdditionalStoresFromAltNames(X509Certificate cert, PkixParameters pkixParams)
		{
			// if in the IssuerAltName extension an URI
			// is given, add an additinal X.509 store
			var issuerAltNames = cert.GetIssuerAlternativeNames();
			if (issuerAltNames != null)
			{
				foreach (var list in issuerAltNames)
				{
					// look for URI
					if (list.Count >= 2 && list[0].Equals(GeneralName.UniformResourceIdentifier))
					{
						string location = (string)list[1];
						AddAdditionalStoreFromLocation(location, pkixParams);
					}
				}
			}
		}

		internal static DateTime GetValidDate(PkixParameters paramsPKIX)
		{
			DateTime? validDate = paramsPKIX.Date;

			if (validDate == null)
				return DateTime.UtcNow;

			return validDate.Value;
		}

		/// <summary>
		/// Returns the issuer of an attribute certificate or certificate.
		/// </summary>
		/// <param name="obj">The attribute certificate or certificate.</param>
		/// <returns>The issuer as <code>X500Principal</code>.</returns>
		internal static X509Name GetIssuerPrincipal(object obj)
		{
			if (obj is X509Certificate cert)
				return cert.IssuerDN;
			if (obj is X509V2AttributeCertificate attrCert)
				return attrCert.Issuer.GetPrincipals()[0];
			throw new InvalidOperationException();
		}

		internal static X509Name GetIssuerPrincipal(X509V2AttributeCertificate attrCert)
		{
			return attrCert.Issuer.GetPrincipals()[0];
		}

		internal static X509Name GetIssuerPrincipal(X509Certificate cert)
		{
			return cert.IssuerDN;
		}

		internal static bool IsSelfIssued(
			X509Certificate cert)
		{
			return cert.SubjectDN.Equivalent(cert.IssuerDN, true);
		}

        internal static AlgorithmIdentifier GetAlgorithmIdentifier(AsymmetricKeyParameter key)
        {
            try
            {
                return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key).Algorithm;
            }
            catch (Exception e)
            {
                throw new PkixCertPathValidatorException("Subject public key cannot be decoded.", e);
            }
        }

		internal static bool IsAnyPolicy(ISet<string> policySet)
		{
			return policySet == null || policySet.Count < 1 || policySet.Contains(ANY_POLICY);
		}

		internal static void AddAdditionalStoreFromLocation(
			string			location,
			PkixParameters	pkixParams)
		{
			if (pkixParams.IsAdditionalLocationsEnabled)
			{
				try
				{
					if (Platform.StartsWith(location, "ldap://"))
					{
						// ldap://directory.d-trust.net/CN=D-TRUST
						// Qualified CA 2003 1:PN,O=D-Trust GmbH,C=DE
						// skip "ldap://"
						location = location.Substring(7);
						// after first / baseDN starts
						string url;//, baseDN;
						int slashPos = location.IndexOf('/');
						if (slashPos != -1)
						{
							url = "ldap://" + location.Substring(0, slashPos);
//							baseDN = location.Substring(slashPos);
						}
						else
						{
							url = "ldap://" + location;
//							baseDN = nsull;
						}

						throw new NotImplementedException("LDAP cert/CRL stores");

						// use all purpose parameters
						//X509LDAPCertStoreParameters ldapParams = new X509LDAPCertStoreParameters.Builder(
						//                                url, baseDN).build();
						//pkixParams.AddAdditionalStore(X509Store.getInstance(
						//    "CERTIFICATE/LDAP", ldapParams));
						//pkixParams.AddAdditionalStore(X509Store.getInstance(
						//    "CRL/LDAP", ldapParams));
						//pkixParams.AddAdditionalStore(X509Store.getInstance(
						//    "ATTRIBUTECERTIFICATE/LDAP", ldapParams));
						//pkixParams.AddAdditionalStore(X509Store.getInstance(
						//    "CERTIFICATEPAIR/LDAP", ldapParams));
					}
				}
				catch (Exception)
				{
					// cannot happen
					throw new Exception("Exception adding X.509 stores.");
				}
			}
		}

		private static BigInteger GetSerialNumber(
			object cert)
		{
			if (cert is X509Certificate)
			{
				return ((X509Certificate)cert).SerialNumber;
			}
			else
			{
				return ((X509V2AttributeCertificate)cert).SerialNumber;
			}
		}

		//
		// policy checking
		//

		internal static HashSet<PolicyQualifierInfo> GetQualifierSet(Asn1Sequence qualifiers)
		{
			var pq = new HashSet<PolicyQualifierInfo>();

			if (qualifiers != null)
            {
				foreach (Asn1Encodable ae in qualifiers)
				{
					try
					{
                        pq.Add(PolicyQualifierInfo.GetInstance(ae.ToAsn1Object()));
                    }
					catch (IOException ex)
					{
						throw new PkixCertPathValidatorException("Policy qualifier info cannot be decoded.", ex);
					}
				}
			}

			return pq;
		}

		internal static PkixPolicyNode RemoveChildlessPolicyNodes(PkixPolicyNode validPolicyTree,
			List<PkixPolicyNode>[] policyNodes, int depthLimit)
		{
			if (validPolicyTree == null)
				return null;

			int i = depthLimit;
			while (--i >= 0)
			{
                var nodes_i = policyNodes[i];

				int j = nodes_i.Count;
				while (--j >= 0)
				{
                    var node_j = nodes_i[j];

					if (node_j.HasChildren)
						continue;

                    nodes_i.RemoveAt(j);

                    var parent = node_j.Parent;
					if (parent == null)
						return null;

                    parent.RemoveChild(node_j);
                }
            }

			return validPolicyTree;
        }

		internal static PkixPolicyNode RemovePolicyNode(PkixPolicyNode validPolicyTree,
			List<PkixPolicyNode>[] policyNodes, PkixPolicyNode _node)
		{
			if (validPolicyTree == null)
				return null;

            PkixPolicyNode _parent = _node.Parent;
            if (_parent == null)
			{
				for (int j = 0; j < policyNodes.Length; j++)
				{
					policyNodes[j].Clear();
				}

				return null;
			}

			_parent.RemoveChild(_node);
			RemovePolicyNodeRecurse(policyNodes, _node);

			return validPolicyTree;
		}

        private static void RemovePolicyNodeRecurse(List<PkixPolicyNode>[] policyNodes, PkixPolicyNode _node)
		{
			policyNodes[_node.Depth].Remove(_node);

			if (_node.HasChildren)
			{
				foreach (PkixPolicyNode _child in _node.Children)
				{
					RemovePolicyNodeRecurse(policyNodes, _child);
				}
			}
		}

        internal static void GetCertStatus(DateTime validDate, X509Crl crl, object cert, CertStatus certStatus)
		{
			X509CrlEntry crl_entry = crl.GetRevokedCertificate(GetSerialNumber(cert));
			if (crl_entry == null)
				return;

			X509Name issuer = GetIssuerPrincipal(cert);

			if (!issuer.Equivalent(crl_entry.GetCertificateIssuer(), true)
				&& !issuer.Equivalent(crl.IssuerDN, true))
            {
                return;
            }

            int reasonCodeValue = CrlReason.Unspecified;

            if (crl_entry.HasExtensions)
            {
				CheckCrlEntryCriticalExtensions(crl_entry, "CRL entry has unsupported critical extensions.");

                try
                {
                    DerEnumerated reasonCode = DerEnumerated.GetInstance(
						GetExtensionValue(crl_entry, X509Extensions.ReasonCode));
                    if (null != reasonCode)
                    {
                        reasonCodeValue = reasonCode.IntValueExact;
                    }
                }
                catch (Exception e)
                {
                    throw new Exception("Reason code CRL entry extension could not be decoded.", e);
                }
            }

            DateTime revocationDate = crl_entry.RevocationDate;
            if (validDate.Ticks < revocationDate.Ticks)
            {
                switch (reasonCodeValue)
                {
                case CrlReason.Unspecified:
                case CrlReason.KeyCompromise:
                case CrlReason.CACompromise:
                case CrlReason.AACompromise:
                    break;
                default:
                    return;
                }
            }

            // (i) or (j)
            certStatus.Status = reasonCodeValue;
            certStatus.RevocationDate = revocationDate;
        }

		/**
		* Return the next working key inheriting DSA parameters if necessary.
		* <p>
		* This methods inherits DSA parameters from the indexed certificate or
		* previous certificates in the certificate chain to the returned
		* <code>PublicKey</code>. The list is searched upwards, meaning the end
		* certificate is at position 0 and previous certificates are following.
		* </p>
		* <p>
		* If the indexed certificate does not contain a DSA key this method simply
		* returns the public key. If the DSA key already contains DSA parameters
		* the key is also only returned.
		* </p>
		*
		* @param certs The certification path.
		* @param index The index of the certificate which contains the public key
		*            which should be extended with DSA parameters.
		* @return The public key of the certificate in list position
		*         <code>index</code> extended with DSA parameters if applicable.
		* @throws Exception if DSA parameters cannot be inherited.
		*/
		internal static AsymmetricKeyParameter GetNextWorkingKey(IList<X509Certificate> certs, int index)
		{
			X509Certificate cert = certs[index];

			AsymmetricKeyParameter pubKey = cert.GetPublicKey();

			if (!(pubKey is DsaPublicKeyParameters dsaPubKey))
				return pubKey;

			if (dsaPubKey.Parameters != null)
				return dsaPubKey;

			for (int i = index + 1; i < certs.Count; i++)
			{
				X509Certificate parentCert = certs[i];
				pubKey = parentCert.GetPublicKey();

				if (!(pubKey is DsaPublicKeyParameters prevDsaPubKey))
				{
					throw new PkixCertPathValidatorException(
						"DSA parameters cannot be inherited from previous certificate.");
				}

				if (prevDsaPubKey.Parameters == null)
					continue;

				DsaParameters dsaParams = prevDsaPubKey.Parameters;

				try
				{
					return new DsaPublicKeyParameters(dsaPubKey.Y, dsaParams);
				}
				catch (Exception exception)
				{
					throw new Exception(exception.Message);
				}
			}

			throw new PkixCertPathValidatorException("DSA parameters cannot be inherited from previous certificate.");
		}

		internal static DateTime GetValidCertDateFromValidityModel(PkixParameters paramsPkix, PkixCertPath certPath,
			int index)
		{
			if (PkixParameters.ChainValidityModel != paramsPkix.ValidityModel || index <= 0)
			{
				// use given signing/encryption/... time (or current date)
				return GetValidDate(paramsPkix);
			}

			var issuedCert = certPath.Certificates[index - 1];

			if (index - 1 == 0)
			{
				// use time when cert was issued, if available
                Asn1GeneralizedTime dateOfCertgen = null;
				try
				{
					byte[] extBytes = issuedCert.GetExtensionValue(IsisMttObjectIdentifiers.IdIsisMttATDateOfCertGen)
						?.GetOctets();
					if (extBytes != null)
					{
                        dateOfCertgen = Asn1GeneralizedTime.GetInstance(extBytes);
                    }
                }
				catch (ArgumentException e)
				{
					throw new Exception("Date of cert gen extension could not be read.", e);
				}
				if (dateOfCertgen != null)
				{
					try
					{
						return dateOfCertgen.ToDateTime();
					}
					catch (ArgumentException e)
					{
						throw new Exception("Date from date of cert gen extension could not be parsed.", e);
					}
				}
			}

			return issuedCert.NotBefore;
		}

		/**
		* Add the CRL issuers from the cRLIssuer field of the distribution point or
		* from the certificate if not given to the issuer criterion of the
		* <code>selector</code>.
		* <p>
		* The <code>issuerPrincipals</code> are a collection with a single
		* <code>X500Principal</code> for <code>X509Certificate</code>s. For
		* {@link X509AttributeCertificate}s the issuer may contain more than one
		* <code>X500Principal</code>.
		* </p>
		*
		* @param dp The distribution point.
		* @param issuerPrincipals The issuers of the certificate or attribute
		*            certificate which contains the distribution point.
		* @param selector The CRL selector.
		* @param pkixParams The PKIX parameters containing the cert stores.
		* @throws Exception if an exception occurs while processing.
		* @throws ClassCastException if <code>issuerPrincipals</code> does not
		* contain only <code>X500Principal</code>s.
		*/
		internal static void GetCrlIssuersFromDistributionPoint(
			DistributionPoint		dp,
			ICollection<X509Name>	issuerPrincipals,
			X509CrlStoreSelector	selector,
			PkixParameters			pkixParameters)
		{
            var issuers = new List<X509Name>();
			// indirect CRL
			if (dp.CrlIssuer != null)
			{
				GeneralName[] genNames = dp.CrlIssuer.GetNames();
				// look for a DN
				for (int j = 0; j < genNames.Length; j++)
				{
					if (genNames[j].TagNo == GeneralName.DirectoryName)
					{
						try
						{
							issuers.Add(X509Name.GetInstance(genNames[j].Name.ToAsn1Object()));
						}
						catch (IOException e)
						{
							throw new Exception("CRL issuer information from distribution point cannot be decoded.", e);
						}
					}
				}
			}
			else
			{
				/*
				 * certificate issuer is CRL issuer, distributionPoint field MUST be
				 * present.
				 */
				if (dp.DistributionPointName == null)
				{
					throw new Exception(
						"CRL issuer is omitted from distribution point but no distributionPoint field present.");
				}

				// add and check issuer principals
				issuers.AddRange(issuerPrincipals);
			}
			// TODO: is not found although this should correctly add the rel name. selector of Sun is buggy here or PKI test case is invalid
			// distributionPoint
			//        if (dp.getDistributionPoint() != null)
			//        {
			//            // look for nameRelativeToCRLIssuer
			//            if (dp.getDistributionPoint().Type == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER)
			//            {
			//                // append fragment to issuer, only one
			//                // issuer can be there, if this is given
			//                if (issuers.size() != 1)
			//                {
			//                    throw new AnnotatedException(
			//                        "nameRelativeToCRLIssuer field is given but more than one CRL issuer is given.");
			//                }
			//                DEREncodable relName = dp.getDistributionPoint().getName();
			//                Iterator it = issuers.iterator();
			//                List issuersTemp = new ArrayList(issuers.size());
			//                while (it.hasNext())
			//                {
			//                    Enumeration e = null;
			//                    try
			//                    {
			//                        e = ASN1Sequence.getInstance(
			//                            new ASN1InputStream(((X500Principal) it.next())
			//                                .getEncoded()).readObject()).getObjects();
			//                    }
			//                    catch (IOException ex)
			//                    {
			//                        throw new AnnotatedException(
			//                            "Cannot decode CRL issuer information.", ex);
			//                    }
			//                    ASN1EncodableVector v = new ASN1EncodableVector();
			//                    while (e.hasMoreElements())
			//                    {
			//                        v.add((DEREncodable) e.nextElement());
			//                    }
			//                    v.add(relName);
			//                    issuersTemp.add(new X500Principal(new DERSequence(v)
			//                        .getDEREncoded()));
			//                }
			//                issuers.clear();
			//                issuers.addAll(issuersTemp);
			//            }
			//        }

			selector.Issuers = issuers;
		}

		/**
		 * Fetches complete CRLs according to RFC 3280.
		 *
		 * @param dp The distribution point for which the complete CRL
		 * @param cert The <code>X509Certificate</code> or
		 *            {@link Org.BouncyCastle.X509.X509AttributeCertificate} for
		 *            which the CRL should be searched.
		 * @param currentDate The date for which the delta CRLs must be valid.
		 * @param paramsPKIX The extended PKIX parameters.
		 * @return A <code>Set</code> of <code>X509CRL</code>s with complete
		 *         CRLs.
		 * @throws Exception if an exception occurs while picking the CRLs
		 *             or no CRLs are found.
		 */
		internal static HashSet<X509Crl> GetCompleteCrls(DistributionPoint dp, object certObj, DateTime currentDate,
			PkixParameters pkixParameters)
		{
			var certObjIssuer = GetIssuerPrincipal(certObj);

			X509CrlStoreSelector crlselect = new X509CrlStoreSelector();
			try
			{
				var issuers = new HashSet<X509Name>();
				issuers.Add(certObjIssuer);

				GetCrlIssuersFromDistributionPoint(dp, issuers, crlselect, pkixParameters);
			}
			catch (Exception e)
			{
				throw new Exception("Could not get issuer information from distribution point.", e);
			}

			if (certObj is X509Certificate cert)
			{
				crlselect.CertificateChecking = cert;
			}
			else if (certObj is X509V2AttributeCertificate attrCert)
			{
				crlselect.AttrCertChecking = attrCert;
			}

			crlselect.CompleteCrlEnabled = true;

			var crls = PkixCrlUtilities.ImplFindCrls(crlselect, pkixParameters, currentDate);
			if (crls.Count < 1)
				throw new Exception("No CRLs found for issuer \"" + certObjIssuer + "\"");

			return crls;
		}

		/**
		 * Fetches delta CRLs according to RFC 3280 section 5.2.4.
		 *
		 * @param currentDate The date for which the delta CRLs must be valid.
		 * @param paramsPKIX The extended PKIX parameters.
		 * @param completeCRL The complete CRL the delta CRL is for.
		 * @return A <code>Set</code> of <code>X509CRL</code>s with delta CRLs.
		 * @throws Exception if an exception occurs while picking the delta
		 *             CRLs.
		 */
		internal static HashSet<X509Crl> GetDeltaCrls(DateTime currentDate, PkixParameters pkixParameters,
			X509Crl completeCRL)
		{
			X509CrlStoreSelector deltaSelect = new X509CrlStoreSelector();

			// 5.2.4 (a)
			try
			{
				var deltaSelectIssuer = new List<X509Name>();
				deltaSelectIssuer.Add(completeCRL.IssuerDN);
				deltaSelect.Issuers = deltaSelectIssuer;
			}
			catch (IOException e)
			{
				throw new Exception("Cannot extract issuer from CRL.", e);
			}

			BigInteger completeCRLNumber = null;
			try
			{
				Asn1Object asn1Object = GetExtensionValue(completeCRL, X509Extensions.CrlNumber);
				if (asn1Object != null)
				{
					completeCRLNumber = CrlNumber.GetInstance(asn1Object).PositiveValue;
				}
			}
			catch (Exception e)
			{
				throw new Exception(
					"CRL number extension could not be extracted from CRL.", e);
			}

			// 5.2.4 (b)
			byte[] idp = null;

			try
			{
				Asn1Object obj = GetExtensionValue(completeCRL, X509Extensions.IssuingDistributionPoint);
				if (obj != null)
				{
					idp = obj.GetEncoded(Asn1Encodable.Der);
				}
			}
			catch (Exception e)
			{
				throw new Exception(
					"Issuing distribution point extension value could not be read.",
					e);
			}

			// 5.2.4 (d)

			deltaSelect.MinCrlNumber = (completeCRLNumber == null)
				?	null
				:	completeCRLNumber.Add(BigInteger.One);

			deltaSelect.IssuingDistributionPoint = idp;
			deltaSelect.IssuingDistributionPointEnabled = true;

			// 5.2.4 (c)
			deltaSelect.MaxBaseCrlNumber = completeCRLNumber;

			// NOTE: Does not restrict to critical DCI extension, so we filter non-critical ones later
			deltaSelect.DeltaCrlIndicatorEnabled = true;

			// find delta CRLs
			var deltaCrls = PkixCrlUtilities.ImplFindCrls(deltaSelect, pkixParameters, currentDate);
			RetainDeltaCrls(deltaCrls);

            /*
			 * TODO[pkix] Implement CRLDP fallback?
			 */
            //if (deltaCrls.Count < 1 &&
            //    Platform.EqualsIgnoreCase("true", Platform.GetEnvironmentVariable("Org.BouncyCastle.X509.EnableCrlDP")))
            //{
            //    CrlDistPoint id = CrlDistPoint.GetInstance(idp);
            //    DistributionPoint[] dps = id.GetDistributionPoints();

            //    for (int i = 0; i < dps.Length; ++i)
            //    {
            //        DistributionPointName dpn = dps[i].DistributionPointName;
            //        if (dpn == null || dpn.Type != DistributionPointName.FullName)
            //            continue;

            //        // Look for URIs in fullName
            //        GeneralName[] genNames = GeneralNames.GetInstance(dpn.Name).GetNames();
            //        for (int j = 0; j < genNames.Length; ++j)
            //        {
            //            GeneralName name = genNames[j];
            //            if (name.TagNo != GeneralName.UniformResourceIdentifier)
            //                continue;

            //            try
            //            {
            //                PKIXCRLStore store = CrlCache.getCrl(certFact, validityDate,
            //                    new URI(((ASN1String)name.getName()).getString()));
            //                if (store != null)
            //                {
            //                    deltaCrls = PkixCrlUtilities.ImplFindCrls(deltaSelect, validityDate, Collections.EMPTY_LIST,
            //                        Collections.singletonList(store)));
            //                    RetainDeltaCrls(deltaCrls);
            //                }
            //                break;
            //            }
            //            catch (Exception)
            //            {
            //                // ignore...  TODO: maybe log
            //            }
            //        }
            //    }
            //}

            return deltaCrls;
        }

        private static bool IsDeltaCrl(X509Crl crl) => HasCriticalExtension(crl, X509Extensions.DeltaCrlIndicator);

        private static void RetainDeltaCrls(HashSet<X509Crl> crls) => crls.RemoveWhere(crl => !IsDeltaCrl(crl));

        internal static void AddAdditionalStoresFromCrlDistributionPoint(CrlDistPoint crldp, PkixParameters pkixParams)
        {
            if (crldp == null)
                return;

            DistributionPoint[] dps;
            try
            {
                dps = crldp.GetDistributionPoints();
            }
            catch (Exception e)
            {
                throw new Exception(
                    "Distribution points could not be read.", e);
            }

            for (int i = 0; i < dps.Length; i++)
            {
                DistributionPointName dpn = dps[i].DistributionPointName;
                // look for URIs in fullName
                if (dpn != null)
                {
                    if (dpn.Type == DistributionPointName.FullName)
                    {
                        GeneralName[] genNames = GeneralNames.GetInstance(dpn.Name).GetNames();
                        // look for an URI
                        for (int j = 0; j < genNames.Length; j++)
                        {
                            if (genNames[j].TagNo == GeneralName.UniformResourceIdentifier)
                            {
                                string location = DerIA5String.GetInstance(genNames[j].Name).GetString();
                                AddAdditionalStoreFromLocation(location, pkixParams);
                            }
                        }
                    }
                }
            }
        }

        internal static bool ProcessCertD1i(int index, IList<PkixPolicyNode>[] policyNodes, DerObjectIdentifier	pOid,
			HashSet<PolicyQualifierInfo> pq)
		{
            var policy = pOid.GetID();

            foreach (var node in policyNodes[index - 1])
			{
				if (node.HasExpectedPolicy(policy))
				{
					var childExpectedPolicies = new HashSet<string>();
					childExpectedPolicies.Add(policy);

                    var child = new PkixPolicyNode(null, index, childExpectedPolicies, node, pq, policy, false);
					node.AddChild(child);
					policyNodes[index].Add(child);

					return true;
				}
			}

			return false;
		}

		internal static void ProcessCertD1ii(int index, IList<PkixPolicyNode>[] policyNodes, DerObjectIdentifier _poid,
			HashSet<PolicyQualifierInfo> _pq)
		{
			var anyPolicyNode = FindValidPolicy(policyNodes[index - 1], ANY_POLICY);
			if (anyPolicyNode != null)
			{
                var policy = _poid.GetID();

                var _childExpectedPolicies = new HashSet<string>();
                _childExpectedPolicies.Add(policy);

                var _child = new PkixPolicyNode(null, index, _childExpectedPolicies, anyPolicyNode, _pq, policy, false);
                anyPolicyNode.AddChild(_child);
                policyNodes[index].Add(_child);
            }
		}

		/**
		* Find the issuer certificates of a given certificate.
		*
		* @param cert
		*            The certificate for which an issuer should be found.
		* @param pkixParams
		* @return A <code>Collection</code> object containing the issuer
		*         <code>X509Certificate</code>s. Never <code>null</code>.
		*
		* @exception Exception
		*                if an error occurs.
		*/
		internal static HashSet<X509Certificate> FindIssuerCerts(X509Certificate cert,
			PkixBuilderParameters pkixBuilderParameters)
		{
			X509CertStoreSelector certSelector = new X509CertStoreSelector();
			try
			{
				certSelector.Subject = cert.IssuerDN;
			}
			catch (IOException ex)
			{
				throw new Exception(
					"Subject criteria for certificate selector to find issuer certificate could not be set.", ex);
			}

			var certs = new HashSet<X509Certificate>();
			try
			{
				CollectionUtilities.CollectMatches(certs, certSelector, pkixBuilderParameters.GetStoresCert());
			}
			catch (Exception e)
			{
				throw new Exception("Issuer certificate cannot be searched.", e);
			}

			return certs;
		}

		internal static Asn1Object GetExtensionValue(IX509Extension extensions, DerObjectIdentifier oid) =>
			X509ExtensionUtilities.FromExtensionValue(extensions, oid);

		internal static void CheckCrlCriticalExtensions(X509Crl crl, string exceptionMessage)
		{
			var c = crl.CertificateList.TbsCertList;
            if (c.Version >= 2)
			{
				var extensions = c.Extensions;
				if (extensions != null)
				{
					foreach (var oid in extensions.ExtensionOids)
					{
                        if (X509Extensions.IssuingDistributionPoint.Equals(oid) ||
                            X509Extensions.DeltaCrlIndicator.Equals(oid))
                        {
                            continue;
                        }

						var extension = extensions.GetExtension(oid);
						if (extension.IsCritical)
							throw new Exception(exceptionMessage);
					}
                }
            }
        }

        internal static void CheckCrlEntryCriticalExtensions(X509CrlEntry crlEntry, string exceptionMessage)
        {
			var extensions = crlEntry.CrlEntry.Extensions;
			if (extensions != null && extensions.HasAnyCriticalExtensions())
				throw new Exception(exceptionMessage);
        }

        internal static PkixPolicyNode FindValidPolicy(IEnumerable<PkixPolicyNode> policyNodes, string policy)
        {
            foreach (var policyNode in policyNodes)
            {
                if (policy.Equals(policyNode.ValidPolicy))
                    return policyNode;
            }
            return null;
        }

        internal static bool HasCriticalExtension(X509Certificate certificate, DerObjectIdentifier extensionOid)
        {
            var c = certificate.CertificateStructure.TbsCertificate;
			return c.Version >= 3 && HasCriticalExtension(c.Extensions, extensionOid);
        }

        internal static bool HasCriticalExtension(X509Crl crl, DerObjectIdentifier extensionOid)
        {
			var c = crl.CertificateList.TbsCertList;
            return c.Version >= 2 && HasCriticalExtension(c.Extensions, extensionOid);
        }

        private static bool HasCriticalExtension(X509Extensions extensions, DerObjectIdentifier extensionOid)
        {
            if (extensions != null)
            {
                var extension = extensions.GetExtension(extensionOid);
                if (extension != null)
                    return extension.IsCritical;
            }
            return false;
        }
    }
}
