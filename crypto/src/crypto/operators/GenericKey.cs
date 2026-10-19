using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Crypto.Operators
{
    /// <summary>A key held as an opaque representation, optionally with the identifier of its algorithm.</summary>
    public class GenericKey
    {
        private readonly AlgorithmIdentifier algorithmIdentifier;
        private readonly object representation;

        /// <summary>Create a new <see cref="GenericKey"/>.</summary>
        /// <param name="representation">The representation.</param>
        public GenericKey(object representation)
        {
            this.algorithmIdentifier = null;
            this.representation = representation;
        }

        /// <summary>Create a new <see cref="GenericKey"/>.</summary>
        /// <param name="algorithmIdentifier">The algorithm identifier.</param>
        /// <param name="representation">The representation.</param>
        public GenericKey(AlgorithmIdentifier algorithmIdentifier, byte[] representation)
        {
            this.algorithmIdentifier = algorithmIdentifier;
            this.representation = representation;
        }

        /// <summary>Create a new <see cref="GenericKey"/>.</summary>
        /// <param name="algorithmIdentifier">The algorithm identifier.</param>
        /// <param name="representation">The representation.</param>
        public GenericKey(AlgorithmIdentifier algorithmIdentifier, object representation)
        {
            this.algorithmIdentifier = algorithmIdentifier;
            this.representation = representation;
        }

        /// <summary>Gets the algorithm identifier of the key, if there is one.</summary>
        public AlgorithmIdentifier AlgorithmIdentifier
        {
            get { return algorithmIdentifier; }
        }

        /// <summary>Gets the representation.</summary>
        public object Representation
        {
            get { return representation; }
        }
    }
}
