namespace Org.BouncyCastle.Pkix
{
    /// <summary>Shape classification of a string-host name-constraint value, fixed at construction.</summary>
    /// <remarks>
    /// The classification precedence mirrors the historical per-comparison dispatch exactly: a '@' at an
    /// index greater than 0 is a particular mailbox (even if the value also begins with '.'); a leading '@'
    /// is the legacy exact-host form; otherwise a leading '.' is a domain (subdomains) constraint; anything
    /// else is a host.
    /// </remarks>
    internal enum NameConstraintHostNameKind : byte
    {
        Mailbox,    // "local@host"
        AtHost,     // "@host"
        Host,       // "host"
        Domain,     // ".domain"
    }
}
