namespace Org.BouncyCastle.Pkix
{
    /// <summary>
    /// The canonical-form contract shared by the string-host name-constraint wrapper types whose subtree
    /// set algebra is the common host-name algebra (see the Relate/Intersect/Union methods of
    /// <see cref="NameConstraintUtilities"/>): <see cref="NameConstraintEmail"/>,
    /// <see cref="NameConstraintUri"/> and <see cref="NameConstraintDns"/> (which classifies everything as
    /// one fixed <see cref="NameConstraintHostNameKind.Domain"/> - every dNSName denotes a subtree).
    /// </summary>
    internal interface INameConstraintHostName
    {
        /// <summary>The shape classification, fixed at construction.</summary>
        NameConstraintHostNameKind Kind { get; }

        /// <summary>The canonical string - the identity.</summary>
        string Value { get; }

        /// <summary>The derived host comparand (for the address kinds, the part after the first '@').</summary>
        string Host { get; }
    }
}
