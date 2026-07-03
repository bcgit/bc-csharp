using System;
using System.Collections.Generic;
using System.Diagnostics;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

using static Org.BouncyCastle.Pkix.NameConstraintRelation;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>An iPAddress constraint (base address || subnet mask) in canonical form for name-constraint
    /// processing.</summary>
    /// <remarks>
    /// Construction is the only way in, and it both canonicalises and validates, so downstream matching and
    /// set-algebra see only canonical CIDR:
    /// <list type="bullet">
    /// <item>The length must be 8 or 32 bytes - anything else throws
    /// <see cref="PkixNameConstraintValidatorException"/> (fail-closed: the certificate path is rejected).</item>
    /// <item>The subnet mask must be a contiguous CIDR prefix. A non-contiguous mask is rejected by default;
    /// with <see cref="Properties.X509AllowLenientIPAddressMask"/> it is instead rounded to the
    /// most-restrictive contiguous mask for the construction context - a permitted range is narrowed (fill up
    /// to the last 1-bit), an excluded range is broadened (keep only the leading 1-bits) - so the salvage can
    /// only tighten validation. This is what keeps <see cref="IntersectIPRange"/> from minting new ranges.</item>
    /// <item>A 32-byte constraint whose address half is IPv4-mapped (RFC 4291 sec. 2.5.5.2) and whose mask
    /// covers the full <c>::ffff:0:0/96</c> prefix is reduced to the 8-byte IPv4 form.</item>
    /// <item>The base's host bits (those cleared by the mask) are zeroed, so equal networks are byte-equal and
    /// dedupe. Matching is unaffected (it masks both operands).</item>
    /// </list>
    /// Equality and hashing are content-based. Use <see cref="CreatePermitted"/> for permitted subtrees and
    /// <see cref="CreateExcluded"/> for excluded subtrees. Tested addresses are the separate (transient)
    /// <see cref="NameConstraintIPAddress"/> type.
    /// </remarks>
    internal readonly struct NameConstraintIPRange
        : IEquatable<NameConstraintIPRange>
    {
        /// <summary>Create a permitted-subtree iPAddress range (a non-contiguous mask, if salvaged, is
        /// narrowed).</summary>
        /// <exception cref="PkixNameConstraintValidatorException"/>
        internal static NameConstraintIPRange CreatePermitted(byte[] octets) => Create(octets, excluded: false);

        /// <summary>Create an excluded-subtree iPAddress range (a non-contiguous mask, if salvaged, is
        /// broadened).</summary>
        /// <exception cref="PkixNameConstraintValidatorException"/>
        internal static NameConstraintIPRange CreateExcluded(byte[] octets) => Create(octets, excluded: true);

        /// <exception cref="PkixNameConstraintValidatorException"/>
        private static NameConstraintIPRange Create(byte[] octets, bool excluded)
        {
            int length = octets.Length;
            if (length != 8 && length != 32)
                throw new PkixNameConstraintValidatorException("iPAddress constraint has invalid length: " + length);

            // Work on a copy: canonicalisation mutates in place and the caller's array may be shared (e.g. an
            // Asn1OctetString's contents).
            byte[] canonical = (byte[])octets.Clone();
            int half = length / 2;

            if (!IsContiguousMask(canonical, half, half))
            {
                // A non-contiguous subnet mask isn't valid CIDR, and OR-ing such masks in IntersectIPRange is
                // what mints new ranges. Reject (fail-closed) unless leniency is enabled, in which case round to
                // the most-restrictive contiguous mask for the context - permitted narrows (fill up to the last
                // 1-bit), excluded broadens (keep only the leading 1-bits). Either way, non-contiguity is gone.
                if (!Properties.GetBoolean(Properties.X509AllowLenientIPAddressMask, false))
                {
                    throw new PkixNameConstraintValidatorException(
                        "iPAddress constraint has a non-contiguous subnet mask");
                }

                WritePrefixMask(canonical, half, half, MaskPrefixLength(canonical, half, half, excluded));
            }

            // Collapse an IPv4-mapped IPv6 constraint (now with a contiguous mask), then zero the base's host
            // bits so equal networks are byte-equal.
            canonical = NormalizeIPv4MappedIPv6Constraint(canonical);
            ZeroHostBits(canonical);

            return new NameConstraintIPRange(canonical);
        }

        private readonly byte[] m_bytes;
        private readonly int m_prefixLength;

        private NameConstraintIPRange(byte[] bytes)
        {
            int half = bytes.Length / 2;
            Debug.Assert(IsContiguousMask(bytes, half, half));

            m_bytes = bytes;
            // For a contiguous mask the index of the first 0-bit IS the prefix length.
            m_prefixLength = MaskPrefixLength(bytes, half, half, excluded: true);
        }

        public bool Equals(NameConstraintIPRange other) => Arrays.AreEqual(m_bytes, other.m_bytes);

        public override bool Equals(object obj) => obj is NameConstraintIPRange other && Equals(other);

        public override int GetHashCode() => Arrays.GetHashCode(m_bytes);

        /// <summary>Stringifies as dotted address bytes, '/', dotted subnet mask bytes.</summary>
        public override string ToString()
        {
            string temp = "";
            for (int i = 0; i < m_bytes.Length / 2; i++)
            {
                temp += (m_bytes[i] & 0x00FF) + ".";
            }
            temp = temp.Substring(0, temp.Length - 1);
            temp += "/";
            for (int i = m_bytes.Length / 2; i < m_bytes.Length; i++)
            {
                temp += (m_bytes[i] & 0x00FF) + ".";
            }
            temp = temp.Substring(0, temp.Length - 1);
            return temp;
        }

        internal static bool IsConstrained(HashSet<NameConstraintIPRange> constraints, NameConstraintIPAddress ip)
        {
            foreach (var constraint in constraints)
            {
                if (IsConstrained(constraint, ip))
                    return true;
            }

            return false;
        }

        /**
         * Checks if the IP address <code>ip</code> is constrained by
         * <code>constraint</code>. Both are canonical by construction -
         * IPv4-mapped IPv6 forms already reduced - so the length pre-filter
         * compares like-for-like address families.
         */
        private static bool IsConstrained(NameConstraintIPRange constraint, NameConstraintIPAddress ip)
        {
            byte[] constraintBytes = constraint.m_bytes, ipBytes = ip.Bytes;

            int ipLength = ipBytes.Length;
            if (ipLength != (constraintBytes.Length / 2))
                return false;

            // Match iff the tested address and the constraint's base address agree on every masked bit.
            // The mask half follows the base half in the constraint, i.e. at offset ipLength.
            for (int i = 0; i < ipLength; i++)
            {
                int mask = constraintBytes[ipLength + i];
                if ((ipBytes[i] & mask) != (constraintBytes[i] & mask))
                    return false;
            }

            return true;
        }

        // Classify the set relationship of range1 to range2 in one pass. Canonical CIDR ranges nest or are
        // disjoint: the ranges overlap iff their bases agree within the shared prefix (the AND of two
        // contiguous masks is the shorter one), and then the prefix lengths decide the direction. Equal
        // prefixes with agreeing bases are byte-equal ranges (bases are host-zeroed).
        private static NameConstraintRelation Relate(NameConstraintIPRange range1, NameConstraintIPRange range2)
        {
            byte[] b1 = range1.m_bytes, b2 = range2.m_bytes;
            if (b1.Length != b2.Length)
                return Disjoint;                // different address families never overlap

            int half = b1.Length / 2;
            for (int i = 0; i < half; i++)
            {
                int common = b1[half + i] & b2[half + i];
                if (((b1[i] ^ b2[i]) & common) != 0)
                    return Disjoint;            // the networks differ within the shared prefix
            }

            int prefix1 = range1.m_prefixLength, prefix2 = range2.m_prefixLength;
            if (prefix1 == prefix2)
                return Equal;

            return prefix1 < prefix2 ? Subsumes : SubsumedBy;   // the shorter prefix is the broader range
        }

        internal static HashSet<NameConstraintIPRange> Intersect(HashSet<NameConstraintIPRange> permitted,
            HashSet<GeneralSubtree> subtrees)
        {
            var intersect = new HashSet<NameConstraintIPRange>();
            foreach (GeneralSubtree subtree in subtrees)
            {
                var ip = CreatePermitted(Asn1OctetString.GetInstance(subtree.Base.Name).GetOctets());

                if (permitted == null)
                {
                    intersect.Add(ip);
                }
                else
                {
                    foreach (var _permitted in permitted)
                    {
                        // The narrower of an overlapping pair is the intersection (already canonical - added
                        // directly). Existing constraint first: an equal pair keeps the first-registered
                        // instance.
                        switch (Relate(_permitted, ip))
                        {
                        case Equal:
                        case SubsumedBy:
                            intersect.Add(_permitted);  // _permitted is the narrower (or equal)
                            break;
                        case Subsumes:
                            intersect.Add(ip);          // ip is the narrower
                            break;
                        case Disjoint:
                            break;                      // no intersection
                        }
                    }
                }
            }
            return intersect;
        }

        internal static HashSet<NameConstraintIPRange> Union(HashSet<NameConstraintIPRange> excluded,
            NameConstraintIPRange ip)
        {
            if (excluded == null)
                return new HashSet<NameConstraintIPRange> { ip };

            // Covered (contained-or-equal; an equal pair keeps the first-registered instance): the union
            // is the existing set, unchanged - precise, unlike bc-java's unionIPRange, which keeps both
            // operands of every overlapping pair. Covered and dropped verdicts are mutually exclusive over
            // a pairwise-non-nested set, so on a covered verdict nothing has been dropped yet and the
            // partial copy is simply abandoned. Otherwise ip replaces whatever it strictly contains. One
            // Relate per range.
            var union = new HashSet<NameConstraintIPRange>();
            foreach (var _excluded in excluded)
            {
                switch (Relate(_excluded, ip))
                {
                case Equal:
                case Subsumes:
                    return excluded;        // ip is covered: the union is the existing set
                case SubsumedBy:
                    break;                  // dropped: ip will represent it
                case Disjoint:
                    union.Add(_excluded);
                    break;
                }
            }
            union.Add(ip);
            return union;
        }

        // Is the len-byte mask at off a contiguous CIDR prefix (leading 1-bits then all 0-bits)?
        private static bool IsContiguousMask(byte[] octets, int off, int len)
        {
            int i = 0;
            while (i < len && octets[off + i] == 0xFF)
            {
                ++i;
            }
            if (i < len)
            {
                // The partial byte must be a left-aligned run of 1s, i.e. its complement is a right-aligned run.
                int c = ~octets[off + i] & 0xFF;
                if ((c & (c + 1)) != 0)
                    return false;

                while (++i < len)
                {
                    if (octets[off + i] != 0)
                        return false;
                }
            }
            return true;
        }

        // The contiguous prefix length to round a non-contiguous mask to: for an excluded range the index of
        // the first 0-bit (truncate at first 0 => broader); for a permitted range one past the last 1-bit
        // (fill up to the last 1 => narrower).
        private static int MaskPrefixLength(byte[] octets, int off, int len, bool excluded)
        {
            int totalBits = len * 8;
            if (excluded)
            {
                for (int bit = 0; bit < totalBits; ++bit)
                {
                    if (!GetBit(octets, off, bit))
                        return bit;
                }
                return totalBits;
            }

            for (int bit = totalBits - 1; bit >= 0; --bit)
            {
                if (GetBit(octets, off, bit))
                    return bit + 1;
            }
            return 0;
        }

        private static bool GetBit(byte[] octets, int off, int bit) =>
            (octets[off + (bit >> 3)] & (0x80 >> (bit & 7))) != 0;

        // Overwrite the len-byte mask at off with a contiguous prefix of prefixBits 1-bits.
        private static void WritePrefixMask(byte[] octets, int off, int len, int prefixBits)
        {
            for (int i = 0; i < len; ++i)
            {
                int rem = prefixBits - i * 8;
                int ones = rem <= 0 ? 0 : (rem >= 8 ? 8 : rem);
                octets[off + i] = ones == 0 ? (byte)0 : (byte)(0xFF << (8 - ones));
            }
        }

        // Zero the base's host bits (those cleared by the mask) so equal networks are byte-equal.
        private static void ZeroHostBits(byte[] octets)
        {
            int half = octets.Length / 2;
            for (int i = 0; i < half; ++i)
            {
                octets[i] &= octets[half + i];
            }
        }

        /**
         * A Name-Constraints iPAddress constraint is encoded as
         * {@code IP || subnet-mask}. If both halves are in IPv4-mapped IPv6
         * form (the IP half matches the {@code ::ffff:0:0/96} prefix and the
         * mask half is all-ones across the first 96 bits), reduce to the
         * 8-byte (4-byte IPv4 || 4-byte mask) form. Otherwise return the
         * constraint unchanged. The mask check matters: a mask narrower than
         * /96 means the constraint is really an IPv6 range that happens to
         * start at an IPv4-mapped address, and collapsing it to IPv4 would
         * change which addresses match.
         */
        private static byte[] NormalizeIPv4MappedIPv6Constraint(byte[] constraint)
        {
            if (constraint.Length != 32)
                return constraint;

            // Address half (offset 0) must be IPv4-mapped, and the mask half (offset 16) must be all-ones
            // across the first 96 bits (its leading 12 bytes).
            if (!NameConstraintUtilities.IsIPv4MappedIPv6Address(constraint, 0))
                return constraint;

            for (int i = 16; i < 28; i++)
            {
                if (constraint[i] != 0xFF)
                    return constraint;
            }

            byte[] result = new byte[8];
            Array.Copy(constraint, 12, result, 0, 4);   // IPv4 address (low 32 bits of the mapped address)
            Array.Copy(constraint, 28, result, 4, 4);   // IPv4 mask (low 32 bits of the mask)
            return result;
        }
    }
}
