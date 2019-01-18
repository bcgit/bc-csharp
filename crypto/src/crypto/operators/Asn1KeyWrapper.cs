using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Operators
{
    public class Asn1KeyWrapper : IKeyWrapper
    {
        private X509Certificate cert;
        private string algorithm;

        public Asn1KeyWrapper(string algorithm, X509Certificate cert)
        {
            this.algorithm = algorithm;
            this.cert = cert;
        }

        public object AlgorithmDetails
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public IBlockResult Wrap(byte[] keyData)
        {
            throw new NotImplementedException();
        }
    }
}
