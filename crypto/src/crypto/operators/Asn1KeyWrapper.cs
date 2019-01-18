using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;

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

    internal class RsaOaepWrapper : IKeyWrapper, IKeyUnwrapper
    {
        private readonly AlgorithmIdentifier algId;
        private readonly IAsymmetricBlockCipher engine;

        RsaOaepWrapper(IDigest digest, DerObjectIdentifier digestOid)
        {
            AlgorithmIdentifier digestAlgId = new AlgorithmIdentifier(digestOid, DerNull.Instance);

            this.algId = new AlgorithmIdentifier(
                PkcsObjectIdentifiers.IdRsaesOaep,
                new RsaesOaepParameters(
                    digestAlgId,
                    new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, digestAlgId),
                    RsaesOaepParameters.DefaultPSourceAlgorithm));
            this.engine = new OaepEncoding(new RsaBlindedEngine());
        }
        public object AlgorithmDetails
        {
            get
            {
                return algId;
            }
        }

        public IBlockResult Unwrap(byte[] cipherText, int offset, int length)
        {
            return new SimpleBlockResult(engine.ProcessBlock(cipherText, offset, length));
        }

        public IBlockResult Wrap(byte[] keyData)
        {
            return new SimpleBlockResult(engine.ProcessBlock(keyData, 0, keyData.Length));
        }
    }
}
