using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X500.Style;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

using static Org.BouncyCastle.Pkix.NameConstraintRelation;

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
            // Relaxed anywhere-match needed for GSMA SGP.22. The cert-path driver triggers it automatically
            // per-chain (the eUICC/EUM policy OIDs, via IsConstrainedSgp22 - see CheckDNSgp22); this property
            // is the manual override for callers using the validator directly, or for chains that omit those
            // markers.
            if (Properties.GetBoolean(Properties.X509Sgp22NameConstraints, false))
                return IsConstrainedSgp22(constraints, directory);

            foreach (var constraint in constraints)
            {
                if (WithinDNSubtree(directory, constraint))
                    return true;
            }

            return false;
        }

        internal static bool IsConstrainedSgp22(HashSet<NameConstraintDN> constraints, NameConstraintDN directory)
        {
            foreach (var constraint in constraints)
            {
                if (WithinDNSubtreeSgp22(directory, constraint))
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

        /// <summary>
        /// Relaxed directoryName subtree matching for GSMA SGP.22 v2.5 (sections 4.5.2.1.0.2 and 4.5.2.1.0.3), enabled
        /// only when <see cref="Properties.X509Sgp22NameConstraints"/> is <c>true</c>.
        /// </summary>
        /// <remarks>
        /// Each RDN of the permitted subtree must be matched by some RDN of the subject DN regardless of position;
        /// additional subject attributes are permitted, and a serialNumber RDN is matched with a StartsWith comparison
        /// wherever it occurs. This deliberately departs from the contiguous prefix matching of RFC 5280 7.1
        /// implemented by the non-SGP22 matching.
        /// </remarks>
        private static bool WithinDNSubtreeSgp22(NameConstraintDN dns, NameConstraintDN subtree)
        {
            Rdn[] dnsRdns = dns.m_rdns, subtreeRdns = subtree.m_rdns;

            // An empty subtree would be a prefix of every DN; treat it as "no match" instead, so an empty permitted
            // base can't nullify the permittedSubtrees restriction.
            if (subtreeRdns.Length < 1)
                return false;

            // A prefix can't be longer than the DN.
            if (subtreeRdns.Length > dnsRdns.Length)
                return false;

            return WithinDNSubtreeSgp22(dnsRdns, subtreeRdns);
        }

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

            // Special treatment of serialNumber for the GSMA SGP.22 RSP specification: the constraint's
            // IIN is a prefix (EID digits 1 to 8) of the subject's EID. The subject side is held to the
            // encoding SGP.22 explicitly mandates (the EID "as a decimal PrintableString"); the constraint
            // side accepts any ASN.1 string form - X.520 binds serialNumber to PrintableString there too,
            // but only by inheritance, and refusing a misencoded trust-side IIN would reject every leaf
            // under that EUM (the historical code read it type-agnostically via ToString). Anything else
            // falls through to ordinary RDN equality below instead of throwing from an ASN.1 accessor.
            if (subtreeRdn.Count == 1 && subtreeFirst.Type.Equals(X509Name.SerialNumber))
            {
                var dnsFirstValue = DerPrintableString.GetOptional(dnsFirst.Value);

                if (dnsFirstValue != null && subtreeFirst.Value.ToAsn1Object() is IAsn1String subtreeFirstValue)
                    return Platform.StartsWith(dnsFirstValue.GetString(), subtreeFirstValue.GetString());
            }

            return IetfUtilities.RdnAreEqual(subtreeRdn, dnsRdn);
        }

        // Classify the set relationship of dn1's subtree to dn2's in one RDN prefix walk. RdnAreEqual is
        // positional and symmetric, so a single walk over the shared prefix reproduces both WithinDNSubtree
        // directions exactly; the length comparison then decides the direction (the shorter sequence is the
        // broader subtree), and equal lengths with an equal prefix mean RDN-equal sequences (Equal, even if
        // differently encoded). The SGP22 relaxed match plays no part here: the spec (SGP.22 v2.6.1 section
        // 4.5.2.2) defines it only for checking a leaf subject against the EUM's constraints (IsConstrained),
        // never for relating constraints to each other - and a conforming SGP.22 chain cannot fold DN
        // constraint sets anyway, its one constraint source being the EUM, a pathLen=0 CA.
        private static NameConstraintRelation Relate(NameConstraintDN dn1, NameConstraintDN dn2)
        {
            Rdn[] rdns1 = dn1.m_rdns, rdns2 = dn2.m_rdns;
            int len1 = rdns1.Length, len2 = rdns2.Length;

            // An empty RDNSequence would be a prefix of everything; it relates to nothing instead - not
            // even another empty - mirroring WithinDNSubtree's guard, so an empty base can neither absorb
            // real subtrees nor collapse into them.
            if (len1 < 1 || len2 < 1)
                return Disjoint;

            int common = len1 < len2 ? len1 : len2;
            for (int i = 0; i < common; i++)
            {
                if (!IetfUtilities.RdnAreEqual(rdns1[i], rdns2[i]))
                    return Disjoint;                        // the sequences diverge within the shared prefix
            }

            if (len1 == len2)
                return Equal;

            return len1 < len2 ? Subsumes : SubsumedBy;     // the shorter prefix is the broader subtree
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
                        // The narrower (deeper) of an overlapping pair is the intersection. Existing
                        // constraint (dn2) first: an equal pair keeps the first-registered instance.
                        switch (Relate(dn2, dn1))
                        {
                        case Equal:
                        case SubsumedBy:
                            intersect.Add(dn2);     // dn2 is the narrower (or equal)
                            break;
                        case Subsumes:
                            intersect.Add(dn1);     // dn1 is the narrower
                            break;
                        case Disjoint:
                            break;                  // no intersection
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

            // In-place union (the caller owns the set - the stored sets are never aliased). Covered
            // (subsumed-or-equal; an equal pair - RDN-equal, even if differently encoded - keeps the
            // first-registered instance): the set is already the union. Otherwise dn replaces whatever it
            // strictly subsumes - removed after the enumeration, which must not mutate the set. One
            // Relate per subtree.
            List<NameConstraintDN> dropped = null;
            foreach (var subtree in excluded)
            {
                switch (Relate(subtree, dn))
                {
                case Equal:
                case Subsumes:
                    return excluded;        // dn is covered: the set is already the union
                case SubsumedBy:
                    dropped = dropped ?? new List<NameConstraintDN>();
                    dropped.Add(subtree);   // dn will represent it
                    break;
                case Disjoint:
                    break;
                }
            }

            if (dropped != null)
            {
                foreach (var d in dropped)
                {
                    excluded.Remove(d);
                }
            }
            excluded.Add(dn);
            return excluded;
        }
    }
}
