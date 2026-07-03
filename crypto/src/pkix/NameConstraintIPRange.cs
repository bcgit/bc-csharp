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
    /// Construction is the only way in, and it both canonicalises and validates: a 32-byte constraint whose
    /// address half is IPv4-mapped (RFC 4291 sec. 2.5.5.2) and whose mask covers the full
    /// <c>::ffff:0:0/96</c> prefix is reduced to the 8-byte IPv4 form, and the result must then be 8 or 32
    /// bytes - anything else throws <see cref="PkixNameConstraintValidatorException"/>, so a structurally
    /// invalid constraint fails closed (the certificate path is rejected) instead of being stored inert.
    /// Equality and hashing are content-based. Tested addresses are the separate (transient)
    /// <see cref="NameConstraintIPAddress"/> type.
    /// </remarks>
    internal readonly struct NameConstraintIPRange
        : IEquatable<NameConstraintIPRange>
    {
        /// <exception cref="PkixNameConstraintValidatorException"/>
        internal static NameConstraintIPRange Create(byte[] octets)
        {
            byte[] canonical = NormalizeIPv4MappedIPv6Constraint(octets);
            int length = canonical.Length;
            if (length != 8 && length != 32)
                throw new PkixNameConstraintValidatorException("iPAddress constraint has invalid length: " + length);

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
                var ip = Create(Asn1OctetString.GetInstance(subtree.Base.Name).GetOctets());

                if (permitted == null)
                {
                    intersect.Add(ip);
                }
                else
                {
                    foreach (var _permitted in permitted)
                    {
                        byte[] intersection = IntersectIPRange(_permitted.m_bytes, ip.m_bytes);
                        if (intersection != null)
                        {
                            // Re-canonicalise: OR-ing the operands' masks can land the result on the
                            // IPv4-mapped /96 block even when neither operand is itself collapsible.
                            intersect.Add(Create(intersection));
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

            // Unlike the host/DN unions, IP ranges aren't simplified by subsumption: deciding whether one
            // range contains another is deferred, so we just keep both operands. Over-approximating an
            // excluded set is always sound ("adding all is not wrong"), and value equality on the set
            // dedupes any exact repeat - the work the bc-java unionIPRange did by hand.
            return new HashSet<NameConstraintIPRange>(excluded) { ip };
        }

        /**
         * Calculates the intersection of two IP ranges.
         *
         * @param ipWithSubmask1 The first IP address with its subnet mask.
         * @param ipWithSubmask2 The second IP address with its subnet mask.
         * @return A single IP address with its subnet mask as a byte array, or null.
         */
        private static byte[] IntersectIPRange(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
        {
            // i.e. no intersection between IPv4 and IPv6 ranges
            if (ipWithSubmask1.Length != ipWithSubmask2.Length)
                return null;

            byte[][] temp = ExtractIPsAndSubnetMasks(ipWithSubmask1, ipWithSubmask2);
            byte[] ip1 = temp[0];
            byte[] subnetmask1 = temp[1];
            byte[] ip2 = temp[2];
            byte[] subnetmask2 = temp[3];

            byte[][] minMax = MinMaxIPs(ip1, subnetmask1, ip2, subnetmask2);
            byte[] min1 = minMax[0];
            byte[] max1 = minMax[1];
            byte[] min2 = minMax[2];
            byte[] max2 = minMax[3];

            byte[] max = Min(max1, max2);
            byte[] min = Max(min1, min2);

            // minimum IP address can't be bigger than max
            if (CompareTo(min, max) > 0)
                return null;

            // OR keeps all significant bits
            byte[] ip = Or(min1, min2);
            byte[] subnetmask = Or(subnetmask1, subnetmask2);
            return Arrays.Concatenate(ip, subnetmask);
        }

        /**
         * Splits the IP addresses and their subnet mask.
         *
         * @param ipWithSubmask1 The first IP address with the subnet mask.
         * @param ipWithSubmask2 The second IP address with the subnet mask.
         * @return An array with four elements: the IP address and the subnet mask
         *         of each operand, in this order.
         */
        private static byte[][] ExtractIPsAndSubnetMasks(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
        {
            int ipLength = ipWithSubmask1.Length / 2;
            byte[] ip1 = new byte[ipLength];
            byte[] subnetmask1 = new byte[ipLength];
            Array.Copy(ipWithSubmask1, 0, ip1, 0, ipLength);
            Array.Copy(ipWithSubmask1, ipLength, subnetmask1, 0, ipLength);

            byte[] ip2 = new byte[ipLength];
            byte[] subnetmask2 = new byte[ipLength];
            Array.Copy(ipWithSubmask2, 0, ip2, 0, ipLength);
            Array.Copy(ipWithSubmask2, ipLength, subnetmask2, 0, ipLength);
            return new byte[][] { ip1, subnetmask1, ip2, subnetmask2 };
        }

        /**
         * Based on the two IP addresses and their subnet masks the IP range is
         * computed for each IP address - subnet mask pair and returned as the
         * minimum IP address and the maximum address of the range.
         *
         * @param ip1         The first IP address.
         * @param subnetmask1 The subnet mask of the first IP address.
         * @param ip2         The second IP address.
         * @param subnetmask2 The subnet mask of the second IP address.
         * @return A array with two elements. The first/second element contains the
         *         min and max IP address of the first/second IP address and its
         *         subnet mask.
         */
        private static byte[][] MinMaxIPs(byte[] ip1, byte[] subnetmask1, byte[] ip2, byte[] subnetmask2)
        {
            int ipLength = ip1.Length;
            byte[] min1 = new byte[ipLength];
            byte[] max1 = new byte[ipLength];

            byte[] min2 = new byte[ipLength];
            byte[] max2 = new byte[ipLength];

            for (int i = 0; i < ipLength; i++)
            {
                min1[i] = (byte)(ip1[i] & subnetmask1[i]);
                max1[i] = (byte)(ip1[i] & subnetmask1[i] | ~subnetmask1[i]);

                min2[i] = (byte)(ip2[i] & subnetmask2[i]);
                max2[i] = (byte)(ip2[i] & subnetmask2[i] | ~subnetmask2[i]);
            }

            return new byte[][] { min1, max1, min2, max2 };
        }

        private static byte[] Max(byte[] ip1, byte[] ip2) => CompareTo(ip1, ip2) > 0 ? ip1 : ip2;

        private static byte[] Min(byte[] ip1, byte[] ip2) => CompareTo(ip1, ip2) < 0 ? ip1 : ip2;

        private static int CompareTo(byte[] ip1, byte[] ip2)
        {
            for (int i = 0; i < ip1.Length; i++)
            {
                int t1 = ip1[i], t2 = ip2[i];
                if (t1 < t2)
                    return -1;
                if (t1 > t2)
                    return 1;
            }
            return 0;
        }

        private static byte[] Or(byte[] ip1, byte[] ip2)
        {
            byte[] temp = new byte[ip1.Length];
            for (int i = 0; i < ip1.Length; i++)
            {
                temp[i] = (byte)(ip1[i] | ip2[i]);
            }
            return temp;
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

            byte[] ipHalf = new byte[16];
            byte[] maskHalf = new byte[16];
            Array.Copy(constraint, 0, ipHalf, 0, 16);
            Array.Copy(constraint, 16, maskHalf, 0, 16);

            if (!NameConstraintUtilities.IsIPv4MappedIPv6Address(ipHalf))
                return constraint;

            for (int i = 0; i < 12; i++)
            {
                if (maskHalf[i] != (byte)0xFF)
                    return constraint;
            }

            byte[] result = new byte[8];
            Array.Copy(ipHalf, 12, result, 0, 4);
            Array.Copy(maskHalf, 12, result, 4, 4);
            return result;
        }
    }
}
