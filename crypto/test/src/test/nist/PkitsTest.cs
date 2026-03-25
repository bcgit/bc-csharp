using System;
using System.Collections.Generic;
using System.Globalization;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tests.Nist
{
    /// <remarks>
    /// Utility class to support PKITS testing of the Cert Path library and associated functions.
    /// </remarks>
    internal class PkitsTest
    {
        private static readonly CompareInfo InvariantCompareInfo = CultureInfo.InvariantCulture.CompareInfo;

        private static readonly Dictionary<string, DerObjectIdentifier> PoliciesByName =
            new Dictionary<string, DerObjectIdentifier>();

        static PkitsTest()
        {
            PoliciesByName.Add("anyPolicy", new DerObjectIdentifier("2.5.29.32.0"));

            var csorTestPolicies = new DerObjectIdentifier("2.16.840.1.101.3.2.1.48");
            PoliciesByName.Add("NIST-test-policy-1", csorTestPolicies.Branch("1"));
            PoliciesByName.Add("NIST-test-policy-2", csorTestPolicies.Branch("2"));
            PoliciesByName.Add("NIST-test-policy-3", csorTestPolicies.Branch("3"));
            PoliciesByName.Add("NIST-test-policy-4", csorTestPolicies.Branch("4"));
            PoliciesByName.Add("NIST-test-policy-5", csorTestPolicies.Branch("5"));
            PoliciesByName.Add("NIST-test-policy-6", csorTestPolicies.Branch("6"));
            PoliciesByName.Add("NIST-test-policy-7", csorTestPolicies.Branch("7"));
            PoliciesByName.Add("NIST-test-policy-8", csorTestPolicies.Branch("8"));
            PoliciesByName.Add("NIST-test-policy-9", csorTestPolicies.Branch("9"));
            PoliciesByName.Add("NIST-test-policy-10", csorTestPolicies.Branch("10"));
        }

        private readonly List<X509Certificate> m_certs = new List<X509Certificate>();
        private readonly List<X509Crl> m_crls = new List<X509Crl>();
        private readonly HashSet<string> m_policies = new HashSet<string>();
        private readonly HashSet<TrustAnchor> m_trustAnchors = new HashSet<TrustAnchor>();

        private PkixCertPath m_certPath;
        private IStore<X509Certificate> m_certStore;
        private IStore<X509Crl> m_crlStore;
        private PkixCertPathValidatorResult m_validatorResult;
        private X509Certificate m_endCert;
        private bool? m_explicitPolicyRequired;
        private bool? m_inhibitAnyPolicy;
        private bool? m_policyMappingInhibited;
        private bool m_deltaCrlsEnabled;

        internal PkitsTest()
        {
            m_trustAnchors.Add(PkitsTestData.GetTrustAnchor("TrustAnchorRootCertificate"));
            WithCrls("TrustAnchorRootCRL");
        }

        internal PkitsTest EnableDeltaCrls(bool enabled)
        {
            m_deltaCrlsEnabled = enabled;
            return this;
        }

        internal PkitsTest WithCerts(params string[] certNames)
        {
            foreach (var certName in certNames)
            {
                m_certs.Add(PkitsTestData.GetCertificate(FixName(certName)));
            }
            return this;
        }

        internal PkitsTest WithCrls(params string[] crlNames)
        {
            foreach (var crlName in crlNames)
            {
                m_crls.Add(PkitsTestData.GetCrl(FixName(crlName)));
            }
            return this;
        }

        internal PkitsTest WithEndEntity(string endCertName)
        {
            m_endCert = PkitsTestData.GetCertificate(FixName(endCertName));
            return this;
        }

        internal PkitsTest WithExplicitPolicyRequired(bool required)
        {
            m_explicitPolicyRequired = required;
            return this;
        }

        internal PkitsTest WithInhibitAnyPolicy(bool inhibitAnyPolicy)
        {
            m_inhibitAnyPolicy = inhibitAnyPolicy;
            return this;
        }

        internal PkitsTest WithPoliciesByName(params string[] policyNames)
        {
            WithPoliciesByOid(ResolvePolicyOids(policyNames));
            return this;
        }

        internal PkitsTest WithPoliciesByOid(params DerObjectIdentifier[] policyOids)
        {
            foreach (var policyOid in policyOids)
            {
                m_policies.Add(policyOid.GetID());
            }
            return this;
        }

        internal PkitsTest WithPolicyMappingInhibited(bool policyMappingInhibited)
        {
            m_policyMappingInhibited = policyMappingInhibited;
            return this;
        }

        internal PkixCertPathValidatorResult DoTest()
        {
            var x509Certs = new List<X509Certificate>();
            x509Certs.Add(m_endCert);
            x509Certs.AddRange(m_certs);

            m_certPath = new PkixCertPath(x509Certs);

            // TODO[pkix] Just m_certs?
            m_certStore = CollectionUtilities.CreateStore(x509Certs);
            m_crlStore = CollectionUtilities.CreateStore(m_crls);

            PkixCertPathValidator validator = new PkixCertPathValidator();
            PkixParameters pkixParams = new PkixParameters(m_trustAnchors);

            pkixParams.AddStoreCert(m_certStore);
            pkixParams.AddStoreCrl(m_crlStore);
            pkixParams.IsRevocationEnabled = true;

            pkixParams.Date = DateTime.Parse("1/1/2010");

            if (m_explicitPolicyRequired.HasValue)
            {
                pkixParams.IsExplicitPolicyRequired = m_explicitPolicyRequired.Value;
            }

            if (m_inhibitAnyPolicy.HasValue)
            {
                pkixParams.IsAnyPolicyInhibited = m_inhibitAnyPolicy.Value;
            }

            if (m_policyMappingInhibited.HasValue)
            {
                pkixParams.IsPolicyMappingInhibited = m_policyMappingInhibited.Value;
            }

            if (m_policies.Count > 0)
            {
                pkixParams.IsExplicitPolicyRequired = true;
                pkixParams.SetInitialPolicies(m_policies);
            }

            pkixParams.IsUseDeltasEnabled = m_deltaCrlsEnabled;

            m_validatorResult = validator.Validate(m_certPath, pkixParams);

            return m_validatorResult;
        }

        internal void DoExceptionTest(int expectedIndex, string expectedMessage)
        {
            try
            {
                DoTest();

                throw new Exception("path accepted when should be rejected");
            }
            catch (PkixCertPathValidatorException e)
            {
                if (expectedIndex != e.Index)
                    throw new Exception("Index did not match: " + expectedIndex + " got " + e.Index);
                if (!Equals(expectedMessage, e.Message))
                    throw new Exception("Message did not match: '" + expectedMessage + "', got '" + e.Message + "'");
            }
        }

        internal void DoExceptionPrefixTest(int expectedIndex, string expectedPrefix)
        {
            try
            {
                DoTest();

                throw new Exception("path accepted when should be rejected");
            }
            catch (PkixCertPathValidatorException e)
            {
                if (expectedIndex != e.Index)
                    throw new Exception("Index did not match: " + expectedIndex + " got " + e.Index);
                if (!StartsWith(e.Message, expectedPrefix))
                    throw new Exception("Prefix did not match: '" + expectedPrefix + "', got '" + e.Message + "'");
            }
        }

        private static bool Equals(string a, string b) =>
            InvariantCompareInfo.Compare(a, b, CompareOptions.Ordinal) == 0;

        private static string FixName(string name) => name.Replace(" ", "").Replace("-", "");

        private static DerObjectIdentifier[] ResolvePolicyOids(params string[] policyNames)
        {
            DerObjectIdentifier[] oids = new DerObjectIdentifier[policyNames.Length];
            int oidsPos = 0;

            foreach (var policyName in policyNames)
            {
                if (!PoliciesByName.TryGetValue(policyName, out var oid))
                {
                    oid = new DerObjectIdentifier(policyName);
                }

                oids[oidsPos++] = oid;
            }

            return oids;
        }

        private static bool StartsWith(string source, string prefix) =>
            InvariantCompareInfo.IsPrefix(source, prefix, CompareOptions.Ordinal);
    }
}
