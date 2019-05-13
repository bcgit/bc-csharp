using System;
using System.Collections;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Operators
{
    public class Asn1KeyWrapper
        : IKeyWrapper
    {
        private string algorithm;
        private IKeyWrapper wrapper;

        public Asn1KeyWrapper(string algorithm, X509Certificate cert)
        {
            this.algorithm = algorithm;
            wrapper = KeyWrapperUtil.WrapperForName(algorithm, cert.GetPublicKey());
        }

        public object AlgorithmDetails
        {
            get { return wrapper.AlgorithmDetails; }
        }

        public IBlockResult Wrap(byte[] keyData)
        {
            return wrapper.Wrap(keyData);
        }
    }

    internal class KeyWrapperUtil
    {
        //
        // Provider 
        //
        private static readonly IDictionary providerMap = Platform.CreateHashtable();

        static KeyWrapperUtil()
        {
            providerMap.Add("RSA/NONE/OAEPWITHSHA1ANDMGF1PADDING", new RsaOaepWrapperProvider(OiwObjectIdentifiers.IdSha1));
            providerMap.Add("RSA/NONE/OAEPWITHSHA224ANDMGF1PADDING", new RsaOaepWrapperProvider(NistObjectIdentifiers.IdSha224));
            providerMap.Add("RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING", new RsaOaepWrapperProvider(NistObjectIdentifiers.IdSha256));
            providerMap.Add("RSA/NONE/OAEPWITHSHA384ANDMGF1PADDING", new RsaOaepWrapperProvider(NistObjectIdentifiers.IdSha384));
            providerMap.Add("RSA/NONE/OAEPWITHSHA512ANDMGF1PADDING", new RsaOaepWrapperProvider(NistObjectIdentifiers.IdSha512));
        }

        public static IKeyWrapper WrapperForName(string algorithm, ICipherParameters parameters)
        {
            WrapperProvider provider = (WrapperProvider)providerMap[Strings.ToUpperCase(algorithm)];

            if (provider == null)
                throw new ArgumentException("could not resolve " + algorithm + " to a KeyWrapper");

            return (IKeyWrapper)provider.CreateWrapper(true, parameters);
        }

        public static IKeyUnwrapper UnwrapperForName(string algorithm, ICipherParameters parameters)
        {
            WrapperProvider provider = (WrapperProvider)providerMap[Strings.ToUpperCase(algorithm)];
            if (provider == null)
                throw new ArgumentException("could not resolve " + algorithm + " to a KeyUnwrapper");

            return (IKeyUnwrapper)provider.CreateWrapper(false, parameters);
        }
    }

    internal interface WrapperProvider
    {
        object CreateWrapper(bool forWrapping, ICipherParameters parameters);
    }

    internal class RsaOaepWrapper : IKeyWrapper, IKeyUnwrapper
    {
        private readonly AlgorithmIdentifier algId;
        private readonly IAsymmetricBlockCipher engine;

        public RsaOaepWrapper(bool forWrapping, ICipherParameters parameters, DerObjectIdentifier digestOid)
        {
            AlgorithmIdentifier digestAlgId = new AlgorithmIdentifier(digestOid, DerNull.Instance);

            this.algId = new AlgorithmIdentifier(
                PkcsObjectIdentifiers.IdRsaesOaep,
                new RsaesOaepParameters(
                    digestAlgId,
                    new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, digestAlgId),
                    RsaesOaepParameters.DefaultPSourceAlgorithm));
            this.engine = new OaepEncoding(new RsaBlindedEngine(), DigestUtilities.GetDigest(digestOid) );
            this.engine.Init(forWrapping, parameters);
        }

        public object AlgorithmDetails
        {
            get { return algId; }
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

    internal class RsaOaepWrapperProvider
        : WrapperProvider
    {
        private readonly DerObjectIdentifier digestOid;

        internal RsaOaepWrapperProvider(DerObjectIdentifier digestOid)
        {
            this.digestOid = digestOid;
        }

        object WrapperProvider.CreateWrapper(bool forWrapping, ICipherParameters parameters)
        {
            return new RsaOaepWrapper(forWrapping, parameters, digestOid);
        }
    }
}
