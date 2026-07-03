using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

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

        private NameConstraintIPRange(byte[] bytes)
        {
            m_bytes = bytes;
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
                        // Canonical CIDR blocks nest or are disjoint, so the intersection is the narrower of
                        // an overlapping pair (already canonical - added directly) or nothing.
                        if (Contains(_permitted, ip))
                        {
                            intersect.Add(ip);
                        }
                        else if (Contains(ip, _permitted))
                        {
                            intersect.Add(_permitted);
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

            // Ranges are canonical CIDR, so subsumption is decidable: drop any _excluded that ip contains,
            // keep the rest, and add ip unless some _excluded contains it. ip is added at most once, and once
            // it is known to be added the second containment test is skipped (the || short-circuits). This is
            // precise, unlike bc-java's unionIPRange, which keeps both operands.
            var union = new HashSet<NameConstraintIPRange>();
            bool addIp = false;
            foreach (var _excluded in excluded)
            {
                if (Contains(ip, _excluded))
                {
                    // ip contains _excluded, so _excluded is dropped and ip represents it.
                    addIp = true;
                }
                else
                {
                    union.Add(_excluded);

                    addIp = addIp || !Contains(_excluded, ip);
                }
            }
            if (addIp)
            {
                union.Add(ip);
            }
            return union;
        }

        // Does the CIDR range <paramref name="outer"/> contain every address of <paramref name="inner"/>?
        // Both are canonical (contiguous mask, host-zeroed base); different families never contain each other.
        private static bool Contains(NameConstraintIPRange outer, NameConstraintIPRange inner)
        {
            byte[] o = outer.m_bytes, n = inner.m_bytes;
            if (o.Length != n.Length)
                return false;

            int half = o.Length / 2;
            for (int i = 0; i < half; i++)
            {
                byte outerMask = o[half + i];
                // outer must be no narrower than inner (its mask bits are a subset of inner's), and inner's
                // base must fall inside outer's network.
                if ((outerMask & n[half + i]) != outerMask)
                    return false;
                if ((n[i] & outerMask) != o[i])
                    return false;
            }
            return true;
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
