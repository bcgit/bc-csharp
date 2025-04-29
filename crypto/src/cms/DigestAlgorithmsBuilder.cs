using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    internal class DigestAlgorithmsBuilder
    {
        private readonly List<AlgorithmIdentifier> m_ordered = new List<AlgorithmIdentifier>();
        private readonly HashSet<UniqueAlgID> m_unique = new HashSet<UniqueAlgID>();
        private readonly IDigestAlgorithmFinder m_digestAlgorithmFinder;

        internal DigestAlgorithmsBuilder(IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            m_digestAlgorithmFinder = digestAlgorithmFinder;
        }

        // TODO[cms] Currently relies on caller to only use this after any 'AddExisting' calls - enforce?
        internal bool Add(AlgorithmIdentifier algID)
        {
            if (algID == null)
                throw new ArgumentNullException(nameof(algID));

            return ImplAdd(GetCanonical(algID));
        }

        internal bool AddExisting(AlgorithmIdentifier algID)
        {
            if (algID == null)
                throw new ArgumentNullException(nameof(algID));

            // Preserve the absent parameters format of existing digest algorithms
            return ImplAdd(algID);
        }

        internal void AddExisting(IEnumerable<AlgorithmIdentifier> algIDs)
        {
            if (algIDs == null)
                throw new ArgumentNullException(nameof(algIDs));

            foreach (var algID in algIDs)
            {
                AddExisting(algID);
            }
        }

        internal Asn1Set Build() => CmsUtilities.ToDLSet(m_ordered);

        internal bool Contains(AlgorithmIdentifier algID) => m_unique.Contains(new UniqueAlgID(algID));

        private bool ImplAdd(AlgorithmIdentifier algID)
        {
            bool result = m_unique.Add(new UniqueAlgID(algID));
            if (result)
            {
                m_ordered.Add(algID);
            }
            return result;
        }

        private AlgorithmIdentifier GetCanonical(AlgorithmIdentifier algID) =>
            X509Utilities.HasAbsentParameters(algID) ? m_digestAlgorithmFinder.Find(algID.Algorithm) : algID;

        private struct UniqueAlgID
            : IEquatable<UniqueAlgID>
        {
            private readonly AlgorithmIdentifier m_algID;
            private readonly int m_hashCode;

            internal UniqueAlgID(AlgorithmIdentifier algID)
            {
                m_algID = algID ?? throw new ArgumentNullException(nameof(algID));
                m_hashCode = CalculateHashCode(algID);
            }

            public override bool Equals(object obj) => obj is UniqueAlgID other && Equivalent(other);

            public override int GetHashCode() => m_hashCode;

            internal AlgorithmIdentifier AlgID => m_algID;

            bool IEquatable<UniqueAlgID>.Equals(UniqueAlgID other) => Equivalent(other);

            private static int CalculateHashCode(AlgorithmIdentifier algID)
            {
                if (X509Utilities.HasAbsentParameters(algID))
                    return algID.Algorithm.GetHashCode();

                return algID.GetHashCode();
            }

            private bool Equivalent(UniqueAlgID other)
            {
                return m_hashCode == other.m_hashCode
                    && X509Utilities.AreEquivalentAlgorithms(m_algID, other.m_algID);
            }
        }
    }
}
