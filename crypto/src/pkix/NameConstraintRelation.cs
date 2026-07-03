namespace Org.BouncyCastle.Pkix
{
    /// <summary>
    /// The set relationship of one string-host name-constraint value to another, as classified by the
    /// <c>Relate</c> extension in <see cref="NameConstraintUtilities"/>. Because a host/mailbox is a single
    /// point and a domain is a subtree, two such constraints never partially overlap - the relationship is
    /// always exactly one of these four.
    /// </summary>
    internal enum NameConstraintRelation
    {
        /// <summary>The two match the same set of names.</summary>
        Equal,
        /// <summary>The two share no names.</summary>
        Disjoint,
        /// <summary>The first strictly contains the second (the first is the broader constraint).</summary>
        Subsumes,
        /// <summary>The first is strictly contained by the second (the first is the narrower constraint).</summary>
        SubsumedBy,
    }
}
