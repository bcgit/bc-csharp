using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X500.Style;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>A directoryName (tested name or constraint) in parsed form for name-constraint processing.</summary>
    /// <remarks>
    /// Construction is the only way in: the RDNSequence is parsed once, here, into its <see cref="Rdn"/>
    /// elements ("parse, don't validate"), so subtree matching operates on structurally valid values by
    /// construction; a sequence whose elements are not RDN-shaped throws from construction, propagating per
    /// the call site's exception policy. All in-library values arrive pre-validated (GeneralName parses
    /// directoryName via X509Name, and the subject DN is re-encoded from one), so only direct callers of the
    /// public Check*DN(Asn1Sequence) methods can trip this. Equality, hashing and display remain those of the
    /// underlying ASN.1 sequence (encoding-based), matching the historical set semantics; note that MATCHING
    /// uses the broader IETF normalized RDN comparison.
    /// </remarks>
    internal readonly struct NameConstraintDN
        : IEquatable<NameConstraintDN>
    {
        internal static NameConstraintDN Create(Asn1Sequence dn) =>
            new NameConstraintDN(dn, dn.MapElements(Rdn.GetInstance));

        private readonly Asn1Sequence m_seq;
        private readonly Rdn[] m_rdns;

        private NameConstraintDN(Asn1Sequence seq, Rdn[] rdns)
        {
            m_seq = seq;
            m_rdns = rdns;
        }

        public bool Equals(NameConstraintDN other) => object.Equals(m_seq, other.m_seq);

        public override bool Equals(object obj) => obj is NameConstraintDN other && Equals(other);

        public override int GetHashCode() => m_seq == null ? 0 : m_seq.GetHashCode();

        public override string ToString() => m_seq == null ? null : m_seq.ToString();

        internal static bool IsConstrained(HashSet<NameConstraintDN> constraints, NameConstraintDN directory)
        {
            foreach (var constraint in constraints)
            {
                if (WithinDNSubtree(directory, constraint))
                    return true;
            }

            return false;
        }

        private static bool WithinDNSubtree(NameConstraintDN dns, NameConstraintDN subtree)
        {
            Rdn[] dnsRdns = dns.m_rdns, subtreeRdns = subtree.m_rdns;

            // An empty subtree would be a prefix of every DN; treat it as "no match" instead, so an empty permitted
            // base can't nullify the permittedSubtrees restriction.
            if (subtreeRdns.Length < 1)
                return false;

            // A prefix can't be longer than the DN.
            if (subtreeRdns.Length > dnsRdns.Length)
                return false;

            // Relaxed anywhere-match needed for GSMA SGP.22, gated behind a property.
            if (Properties.GetBoolean(Properties.X509Sgp22NameConstraints, false))
                return WithinDNSubtreeSgp22(dnsRdns, subtreeRdns);

            // RFC 5280 4.2.1.10 / 7.1: a directoryName constraint is satisfied only when the constraint's RDNSequence
            // is an initial prefix of the subject's. Match from index 0 only - searching for the constraint's first RDN
            // at an arbitrary offset let an attacker prepend RDNs ahead of the permitted sequence (e.g. a subject
            // C=FR,O=Attacker,C=US,O=TrustedOrg,CN=x being judged inside permitted subtree C=US,O=TrustedOrg) and still
            // pass the permittedSubtrees check.

            for (int j = 0; j < subtreeRdns.Length; j++)
            {
                // Obey RFC 5280 7.1. Two relative distinguished names RDN1 and RDN2 match if they have the same number
                // of naming attributes and for each naming attribute in RDN1 there is a matching naming attribute in
                // RDN2. NOTE: this is now different from the RFC 3280 version, where only binary comparison was used.
                if (!IetfUtilities.RdnAreEqual(subtreeRdns[j], dnsRdns[j]))
                    return false;
            }

            return true;
        }

        /**
         * Relaxed directoryName subtree matching for GSMA SGP.22 v2.5 (sections 4.5.2.1.0.2 and
         * 4.5.2.1.0.3), enabled only when {@link Properties#X509_SGP22_NAME_CONSTRAINTS} is set. Each
         * RDN of the permitted subtree must be matched by some RDN of the subject DN regardless of
         * position; additional subject attributes are permitted, and a serialNumber RDN is matched with
         * a startsWith comparison wherever it occurs. This deliberately departs from the contiguous
         * prefix matching of RFC 5280 7.1 implemented by {@link #WithinDNSubtree}.
         */
        private static bool WithinDNSubtreeSgp22(Rdn[] dnsRdns, Rdn[] subtreeRdns)
        {
            foreach (Rdn subtreeRdn in subtreeRdns)
            {
                if (!RdnMatchesSgp22Any(subtreeRdn, dnsRdns))
                    return false;
            }
            return true;
        }

        private static bool RdnMatchesSgp22Any(Rdn subtreeRdn, Rdn[] dnsRdns)
        {
            foreach (Rdn dnsRdn in dnsRdns)
            {
                if (RdnMatchesSgp22(subtreeRdn, dnsRdn))
                    return true;
            }
            return false;
        }

        private static bool RdnMatchesSgp22(Rdn subtreeRdn, Rdn dnsRdn)
        {
            if (subtreeRdn.Count != dnsRdn.Count)
                return false;

            var subtreeFirst = subtreeRdn.GetFirst();
            var dnsFirst = dnsRdn.GetFirst();

            if (!subtreeFirst.Type.Equals(dnsFirst.Type))
                return false;

            // special treatment of serialNumber for GSMA SGP.22 RSP specification
            if (subtreeRdn.Count == 1 && subtreeFirst.Type.Equals(X509Name.SerialNumber))
            {
                var subtreeFirstValue = DerPrintableString.GetInstance(subtreeFirst.Value).GetString();
                var dnsFirstValue = DerPrintableString.GetInstance(dnsFirst.Value).GetString();
                return Platform.StartsWith(dnsFirstValue, subtreeFirstValue);
            }

            return IetfUtilities.RdnAreEqual(subtreeRdn, dnsRdn);
        }

        internal static HashSet<NameConstraintDN> Intersect(HashSet<NameConstraintDN> permitted,
            HashSet<GeneralSubtree> subtrees)
        {
            var intersect = new HashSet<NameConstraintDN>();
            foreach (GeneralSubtree subtree in subtrees)
            {
                var dn1 = Create(Asn1Sequence.GetInstance(subtree.Base.Name));

                if (permitted == null)
                {
                    intersect.Add(dn1);
                }
                else
                {
                    foreach (var dn2 in permitted)
                    {
                        if (WithinDNSubtree(dn1, dn2))
                        {
                            intersect.Add(dn1);
                        }
                        else if (WithinDNSubtree(dn2, dn1))
                        {
                            intersect.Add(dn2);
                        }
                    }
                }
            }
            return intersect;
        }

        internal static HashSet<NameConstraintDN> Union(HashSet<NameConstraintDN> excluded, NameConstraintDN dn)
        {
            if (excluded == null)
                return new HashSet<NameConstraintDN> { dn };

            var union = new HashSet<NameConstraintDN>();

            foreach (var subtree in excluded)
            {
                if (WithinDNSubtree(dn, subtree))
                {
                    union.Add(subtree);
                }
                else if (WithinDNSubtree(subtree, dn))
                {
                    union.Add(dn);
                }
                else
                {
                    union.Add(subtree);
                    union.Add(dn);
                }
            }

            return union;
        }
    }
}
