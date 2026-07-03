using System;
using System.Collections.Generic;
using System.Diagnostics;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>Name canonicalisation and matching helpers for name-constraint processing.</summary>
    internal static class NameConstraintUtilities
    {
        internal static string ExtractHostFromURL(string url)
        {
            // RFC 3986 §3.2 authority structure:
            //   authority = [ userinfo "@" ] host [ ":" port ]
            // The strip order is: scheme → "//" → path/query/fragment terminator → userinfo (last '@') → host
            // with optional bracketed IPv6 / trailing ":port".
            string sub = url;
            int schemeEnd = sub.IndexOf(':');
            if (schemeEnd >= 0)
            {
                sub = sub.Substring(schemeEnd + 1);
            }
            if (Platform.StartsWith(sub, "//"))
            {
                sub = sub.Substring(2);
            }
            for (int i = 0; i < sub.Length; ++i)
            {
                char c = sub[i];
                if (c == '/' || c == '?' || c == '#')
                {
                    sub = sub.Substring(0, i);
                    break;
                }
            }
            int atPos = sub.LastIndexOf('@');
            if (atPos >= 0)
            {
                sub = sub.Substring(atPos + 1);
            }
            if (Platform.StartsWith(sub, "["))
            {
                int closeBracket = sub.IndexOf(']');
                if (closeBracket > 0)
                {
                    return sub.Substring(1, closeBracket - 1);
                }
                return sub.Substring(1);
            }
            int portColon = sub.LastIndexOf(':');
            if (portColon >= 0)
            {
                sub = sub.Substring(0, portColon);
            }
            return sub;
        }

        internal static string ExtractIA5String(GeneralSubtree subtree)
        {
            GeneralName baseName = subtree.Base;
            Debug.Assert(baseName.TagNo == GeneralName.Rfc822Name
                || baseName.TagNo == GeneralName.DnsName
                || baseName.TagNo == GeneralName.UniformResourceIdentifier);
            return ExtractIA5String(baseName.Name);
        }

        /// <summary>
        /// Reads a GeneralName value as an IA5String. Only valid for the IA5String-valued GeneralName
        /// choices - rfc822Name, dNSName and uniformResourceIdentifier - so callers must dispatch on the
        /// tag first; any other value throws the same ArgumentException a malformed name would, propagating
        /// per the call site's exception policy.
        /// </summary>
        internal static string ExtractIA5String(Asn1Encodable nameValue) =>
            DerIA5String.GetInstance(nameValue).GetString();

        /// <summary>
        /// Does <paramref name="constraint"/> constrain <paramref name="dns"/>, i.e. is the name equal to the
        /// constraint or within its domain? Both arguments must already be in canonical form (RFC 1034
        /// trailing dot stripped); a leading dot on the constraint restricts it to proper subdomains.
        /// </summary>
        internal static bool IsDnsMatch(string constraint, string dns) =>
            Platform.EqualsIgnoreCase(dns, constraint) || WithinDomain(dns, constraint);

        /// <summary>Is <paramref name="ip"/> a 16-byte IPv4-mapped IPv6 address (RFC 4291 sec. 2.5.5.2)?</summary>
        internal static bool IsIPv4MappedIPv6Address(byte[] ip) =>
            ip != null && ip.Length == 16 && IsIPv4MappedIPv6Address(ip, 0);

        /// <summary>Is the 16-byte span at <paramref name="off"/> an IPv4-mapped IPv6 address (RFC 4291
        /// sec. 2.5.5.2)? The caller must ensure 16 bytes are available from <paramref name="off"/>.</summary>
        internal static bool IsIPv4MappedIPv6Address(byte[] ip, int off)
        {
            for (int i = 0; i < 10; i++)
            {
                if (ip[off + i] != 0)
                    return false;
            }
            return ip[off + 10] == (byte)0xFF && ip[off + 11] == (byte)0xFF;
        }

        internal static string StripTrailingDot(string s)
        {
            // length > 1 so a single bare "." (theoretically the empty-label
            // root) is preserved rather than reduced to "".
            if (s != null && s.Length > 1 && s[s.Length - 1] == '.')
                return s.Substring(0, s.Length - 1);

            return s;
        }

        internal static bool WithinDomain(string testDomain, string domain)
        {
            if (Platform.StartsWith(domain, "."))
            {
                domain = domain.Substring(1);
            }

            // Strip the RFC 1034 root-label trailing dot so the per-label
            // compare doesn't see a phantom empty label.
            testDomain = StripTrailingDot(testDomain);
            domain = StripTrailingDot(domain);

            string[] domainParts = Strings.Split(domain, '.');
            string[] testDomainParts = Strings.Split(testDomain, '.');

            // must have at least one subdomain
            if (testDomainParts.Length <= domainParts.Length)
                return false;

            int d = testDomainParts.Length - domainParts.Length;
            if (testDomainParts[d - 1].Length < 1)
                return false;

            for (int i = 0; i < domainParts.Length; i++)
            {
                if (!Platform.EqualsIgnoreCase(domainParts[i], testDomainParts[d + i]))
                    return false;
            }
            return true;
        }

        // The pairwise subtree set algebra shared by the rfc822Name and uniformResourceIdentifier wrapper
        // types (the URI logic has been a verbatim clone of the rfc822Name logic since long before those
        // types existed). The struct constraint keeps the interface dispatch JIT-specialized: no boxing.

        /**
         * The most restricting part from <code>name1</code> and
         * <code>name2</code> is added to the intersection <code>intersect</code>.
         *
         * @param name1     Host-name constraint 1.
         * @param name2     Host-name constraint 2.
         * @param intersect The intersection.
         */
        internal static void Intersect<T>(T name1, T name2, HashSet<T> intersect)
            where T : struct, INameConstraintHostName, IEquatable<T>
        {
            // name1 is a particular address
            if (IsParticularAddress(name1.Kind))
            {
                // both are a particular address
                if (IsParticularAddress(name2.Kind))
                {
                    if (Platform.EqualsIgnoreCase(name1.Value, name2.Value))
                    {
                        intersect.Add(name1);
                    }
                }
                // name2 specifies a domain
                else if (name2.Kind == NameConstraintKind.Domain)
                {
                    if (WithinDomain(name1.Host, name2.Value))
                    {
                        intersect.Add(name1);
                    }
                }
                // name2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(name1.Host, name2.Value))
                    {
                        intersect.Add(name1);
                    }
                }
            }
            // name1 specifies a domain
            else if (name1.Kind == NameConstraintKind.Domain)
            {
                if (IsParticularAddress(name2.Kind))
                {
                    if (WithinDomain(name2.Host, name1.Value))
                    {
                        intersect.Add(name2);
                    }
                }
                // name2 specifies a domain
                else if (name2.Kind == NameConstraintKind.Domain)
                {
                    if (IsDnsMatch(name2.Value, name1.Value))
                    {
                        intersect.Add(name1);
                    }
                    else if (WithinDomain(name2.Value, name1.Value))
                    {
                        intersect.Add(name2);
                    }
                    else
                    {
                        // No intersection
                    }
                }
                else
                {
                    if (WithinDomain(name2.Value, name1.Value))
                    {
                        intersect.Add(name2);
                    }
                }
            }
            // name1 specifies a host
            else
            {
                if (IsParticularAddress(name2.Kind))
                {
                    if (Platform.EqualsIgnoreCase(name2.Host, name1.Value))
                    {
                        intersect.Add(name2);
                    }
                }
                // name2 specifies a domain
                else if (name2.Kind == NameConstraintKind.Domain)
                {
                    if (WithinDomain(name1.Value, name2.Value))
                    {
                        intersect.Add(name1);
                    }
                }
                // name2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(name1.Value, name2.Value))
                    {
                        intersect.Add(name1);
                    }
                }
            }
        }

        private static bool IsParticularAddress(NameConstraintKind kind) =>
            kind == NameConstraintKind.Mailbox || kind == NameConstraintKind.AtHost;

        /**
         * The common part of <code>name1</code> and <code>name2</code> is
         * added to the union <code>union</code>. If <code>name1</code> and
         * <code>name2</code> have nothing in common they are added both.
         *
         * @param name1 Host-name constraint 1.
         * @param name2 Host-name constraint 2.
         * @param union The union.
         */
        internal static void Union<T>(T name1, T name2, HashSet<T> union)
            where T : struct, INameConstraintHostName, IEquatable<T>
        {
            // name1 is a particular address
            if (IsParticularAddress(name1.Kind))
            {
                // both are a particular address
                if (IsParticularAddress(name2.Kind))
                {
                    if (Platform.EqualsIgnoreCase(name1.Value, name2.Value))
                    {
                        union.Add(name1);
                    }
                    else
                    {
                        union.Add(name1);
                        union.Add(name2);
                    }
                }
                // name2 specifies a domain
                else if (name2.Kind == NameConstraintKind.Domain)
                {
                    if (WithinDomain(name1.Host, name2.Value))
                    {
                        union.Add(name2);
                    }
                    else
                    {
                        union.Add(name1);
                        union.Add(name2);
                    }
                }
                // name2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(name1.Host, name2.Value))
                    {
                        union.Add(name2);
                    }
                    else
                    {
                        union.Add(name1);
                        union.Add(name2);
                    }
                }
            }
            // name1 specifies a domain
            else if (name1.Kind == NameConstraintKind.Domain)
            {
                if (IsParticularAddress(name2.Kind))
                {
                    if (WithinDomain(name2.Host, name1.Value))
                    {
                        union.Add(name1);
                    }
                    else
                    {
                        union.Add(name1);
                        union.Add(name2);
                    }
                }
                // name2 specifies a domain
                else if (name2.Kind == NameConstraintKind.Domain)
                {
                    if (IsDnsMatch(name2.Value, name1.Value))
                    {
                        union.Add(name2);
                    }
                    else if (WithinDomain(name2.Value, name1.Value))
                    {
                        union.Add(name1);
                    }
                    else
                    {
                        union.Add(name1);
                        union.Add(name2);
                    }
                }
                else
                {
                    if (WithinDomain(name2.Value, name1.Value))
                    {
                        union.Add(name1);
                    }
                    else
                    {
                        union.Add(name1);
                        union.Add(name2);
                    }
                }
            }
            // name1 specifies a host
            else
            {
                if (IsParticularAddress(name2.Kind))
                {
                    if (Platform.EqualsIgnoreCase(name2.Host, name1.Value))
                    {
                        union.Add(name1);
                    }
                    else
                    {
                        union.Add(name1);
                        union.Add(name2);
                    }
                }
                // name2 specifies a domain
                else if (name2.Kind == NameConstraintKind.Domain)
                {
                    if (WithinDomain(name1.Value, name2.Value))
                    {
                        union.Add(name2);
                    }
                    else
                    {
                        union.Add(name1);
                        union.Add(name2);
                    }
                }
                // name2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(name1.Value, name2.Value))
                    {
                        union.Add(name1);
                    }
                    else
                    {
                        union.Add(name1);
                        union.Add(name2);
                    }
                }
            }
        }
    }
}
