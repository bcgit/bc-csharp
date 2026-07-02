using System;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>A tested iPAddress name in canonical form for name-constraint processing.</summary>
    /// <remarks>
    /// Construction is the only way in, and it both canonicalises and validates: an IPv4-mapped IPv6 address
    /// (RFC 4291 sec. 2.5.5.2) is reduced to its 4-byte IPv4 form, and the result must then be 4 or 16 bytes -
    /// anything else throws <see cref="PkixNameConstraintValidatorException"/>, so a structurally invalid
    /// iPAddress fails closed (the certificate path is rejected) instead of silently failing to match. Tested
    /// addresses are transient: matched against <see cref="NameConstraintIPRange"/> constraints, never stored.
    /// </remarks>
    internal readonly struct NameConstraintIPAddress
    {
        /// <exception cref="PkixNameConstraintValidatorException"/>
        internal static NameConstraintIPAddress Create(byte[] octets)
        {
            byte[] canonical = NormalizeIPv4MappedIPv6Address(octets);
            int length = canonical.Length;
            if (length != 4 && length != 16)
                throw new PkixNameConstraintValidatorException("iPAddress name has invalid length: " + length);

            return new NameConstraintIPAddress(canonical);
        }

        private readonly byte[] m_bytes;

        private NameConstraintIPAddress(byte[] bytes)
        {
            m_bytes = bytes;
        }

        internal byte[] Bytes => m_bytes;

        /**
         * If {@code ip} is a 16-byte IPv4-mapped IPv6 address (RFC 4291
         * sec. 2.5.5.2: leading 80 bits zero, next 16 bits all-ones, trailing
         * 32 bits the IPv4 address), return the 4-byte IPv4 form; otherwise
         * return {@code ip} unchanged.
         */
        private static byte[] NormalizeIPv4MappedIPv6Address(byte[] ip)
        {
            if (!NameConstraintUtilities.IsIPv4MappedIPv6Address(ip))
                return ip;

            byte[] ipv4 = new byte[4];
            Array.Copy(ip, 12, ipv4, 0, 4);
            return ipv4;
        }
    }
}
