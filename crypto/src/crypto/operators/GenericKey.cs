using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Crypto.Operators
{
    public class GenericKey
    {
        private AlgorithmIdentifier algorithmIdentifier;
        private object representation;

        public GenericKey(object representation)
        {
            algorithmIdentifier = null;
            this.representation = representation;
        }

        public GenericKey(AlgorithmIdentifier algorithmIdentifier, byte[] representation)
        {
            this.algorithmIdentifier = algorithmIdentifier;
            this.representation = representation;
        }

        public GenericKey(AlgorithmIdentifier algorithmIdentifier, object representation)
        {
            this.algorithmIdentifier = algorithmIdentifier;
            this.representation = representation;
        }

        public AlgorithmIdentifier AlgorithmIdentifier
        {
            get { return algorithmIdentifier; }
        }

        public object Representation
        {
            get { return representation; }
        }
    }
}
