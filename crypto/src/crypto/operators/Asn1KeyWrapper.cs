using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Operators
{
    public class Asn1KeyWrapper
        : IKeyWrapper
    {
        private readonly IKeyWrapper m_wrapper;

        public Asn1KeyWrapper(string algorithm, X509Certificate cert)
             : this(algorithm, cert.GetPublicKey())
        {
        }

        public Asn1KeyWrapper(string algorithm, ICipherParameters key)
        {
            m_wrapper = KeyWrapperUtil.WrapperForName(algorithm, key);
        }

        public Asn1KeyWrapper(DerObjectIdentifier algorithm, X509Certificate cert)
             : this(algorithm, null, cert.GetPublicKey())
        {
        }

        public Asn1KeyWrapper(DerObjectIdentifier algorithm, ICipherParameters key)
            : this(algorithm, null, key)
        {
        }

        public Asn1KeyWrapper(AlgorithmIdentifier algorithm, X509Certificate cert)
            : this(algorithm.Algorithm, algorithm.Parameters, cert.GetPublicKey())
        {
        }

        public Asn1KeyWrapper(DerObjectIdentifier algorithm, Asn1Encodable parameters, X509Certificate cert)
            : this(algorithm, parameters, cert.GetPublicKey())
        {
        }

        public Asn1KeyWrapper(AlgorithmIdentifier algorithm, ICipherParameters key)
            : this(algorithm.Algorithm, algorithm.Parameters, key)
        {
        }

        public Asn1KeyWrapper(DerObjectIdentifier algorithm, Asn1Encodable parameters, ICipherParameters key)
        {
            if (PkcsObjectIdentifiers.IdRsaesOaep.Equals(algorithm))
            {
                RsaesOaepParameters oaepParams = RsaesOaepParameters.GetInstance(parameters);
                AlgorithmIdentifier mgfAlgID = oaepParams.MaskGenAlgorithm;

                if (PkcsObjectIdentifiers.IdMgf1.Equals(mgfAlgID.Algorithm))
                {
                    mgfAlgID = AlgorithmIdentifier.GetInstance(mgfAlgID.Parameters);
                }

                m_wrapper = new RsaOaepWrapper(forWrapping: true, key, oaepParams.HashAlgorithm.Algorithm,
                    mgfAlgID.Algorithm);
            }
            else if (PkcsObjectIdentifiers.RsaEncryption.Equals(algorithm))
            {
                m_wrapper = new RsaPkcs1Wrapper(forWrapping: true, key);
            }
            else
            {
                throw new ArgumentException("unknown algorithm: " + algorithm);
            }
        }

        public object AlgorithmDetails => m_wrapper.AlgorithmDetails;

        public IBlockResult Wrap(byte[] keyData) => m_wrapper.Wrap(keyData);
    }

    public class Asn1KeyUnwrapper
        : IKeyUnwrapper
    {
        private readonly IKeyUnwrapper m_unwrapper;

        public Asn1KeyUnwrapper(string algorithm, ICipherParameters key)
        {
            m_unwrapper = KeyWrapperUtil.UnwrapperForName(algorithm, key);
        }

        public Asn1KeyUnwrapper(DerObjectIdentifier algorithm, ICipherParameters key)
            : this(algorithm, parameters: null, key)
        {
        }

        public Asn1KeyUnwrapper(DerObjectIdentifier algorithm, Asn1Encodable parameters, ICipherParameters key)
        {
            if (PkcsObjectIdentifiers.IdRsaesOaep.Equals(algorithm))
            {
                RsaesOaepParameters oaepParams = RsaesOaepParameters.GetInstance(parameters);
                AlgorithmIdentifier mgfAlgID = oaepParams.MaskGenAlgorithm;

                if (PkcsObjectIdentifiers.IdMgf1.Equals(mgfAlgID.Algorithm))
                {
                    mgfAlgID = AlgorithmIdentifier.GetInstance(mgfAlgID.Parameters);
                }

                m_unwrapper = new RsaOaepWrapper(forWrapping: false, key, oaepParams.HashAlgorithm.Algorithm,
                    mgfAlgID.Algorithm);
            }
            else if (PkcsObjectIdentifiers.RsaEncryption.Equals(algorithm))
            {
                m_unwrapper = new RsaPkcs1Wrapper(forWrapping: false, key);
            }
            else
            {
                throw new ArgumentException("unknown algorithm: " + algorithm);
            }
        }

        public object AlgorithmDetails => m_unwrapper.AlgorithmDetails;

        public IBlockResult Unwrap(byte[] keyData, int offSet, int length) =>
            m_unwrapper.Unwrap(keyData, offSet, length);
    }

    internal class KeyWrapperUtil
    {
        //
        // Provider 
        //
        private static readonly Dictionary<string, WrapperProvider> m_providerMap =
            new Dictionary<string, WrapperProvider>(StringComparer.OrdinalIgnoreCase);

        static KeyWrapperUtil()
        {
            m_providerMap.Add("RSA/ECB/PKCS1PADDING", new RsaPkcs1WrapperProvider());
            m_providerMap.Add("RSA/NONE/PKCS1PADDING", new RsaPkcs1WrapperProvider());
            m_providerMap.Add("RSA/NONE/OAEPWITHSHA1ANDMGF1PADDING",
                new RsaOaepWrapperProvider(OiwObjectIdentifiers.IdSha1));
            m_providerMap.Add("RSA/NONE/OAEPWITHSHA224ANDMGF1PADDING",
                new RsaOaepWrapperProvider(NistObjectIdentifiers.IdSha224));
            m_providerMap.Add("RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING",
                new RsaOaepWrapperProvider(NistObjectIdentifiers.IdSha256));
            m_providerMap.Add("RSA/NONE/OAEPWITHSHA384ANDMGF1PADDING",
                new RsaOaepWrapperProvider(NistObjectIdentifiers.IdSha384));
            m_providerMap.Add("RSA/NONE/OAEPWITHSHA512ANDMGF1PADDING",
                new RsaOaepWrapperProvider(NistObjectIdentifiers.IdSha512));
            m_providerMap.Add("RSA/NONE/OAEPWITHSHA256ANDMGF1WITHSHA1PADDING",
                new RsaOaepWrapperProvider(NistObjectIdentifiers.IdSha256, OiwObjectIdentifiers.IdSha1));
        }

        public static IKeyWrapper WrapperForName(string algorithm, ICipherParameters parameters)
        {
            if (!m_providerMap.TryGetValue(algorithm, out var provider))
                throw new ArgumentException("could not resolve " + algorithm + " to a KeyWrapper");

            return (IKeyWrapper)provider.CreateWrapper(true, parameters);
        }

        public static IKeyUnwrapper UnwrapperForName(string algorithm, ICipherParameters parameters)
        {
            if (!m_providerMap.TryGetValue(algorithm, out var provider))
                throw new ArgumentException("could not resolve " + algorithm + " to a KeyUnwrapper");

            return (IKeyUnwrapper)provider.CreateWrapper(false, parameters);
        }
    }

    internal interface WrapperProvider
    {
        object CreateWrapper(bool forWrapping, ICipherParameters parameters);
    }

    internal class RsaPkcs1Wrapper
        : IKeyWrapper, IKeyUnwrapper
    {
        private readonly AlgorithmIdentifier m_algID;
        private readonly IAsymmetricBlockCipher m_engine;

        public RsaPkcs1Wrapper(bool forWrapping, ICipherParameters parameters)
        {
            m_algID = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
            m_engine = new Pkcs1Encoding(new RsaBlindedEngine());
            m_engine.Init(forWrapping, parameters);
        }

        public object AlgorithmDetails => m_algID;

        public IBlockResult Unwrap(byte[] cipherText, int offset, int length) =>
            new SimpleBlockResult(m_engine.ProcessBlock(cipherText, offset, length));

        public IBlockResult Wrap(byte[] keyData) =>
            new SimpleBlockResult(m_engine.ProcessBlock(keyData, 0, keyData.Length));
    }

    internal class RsaPkcs1WrapperProvider
        : WrapperProvider
    {
        internal RsaPkcs1WrapperProvider()
        {
        }

        object WrapperProvider.CreateWrapper(bool forWrapping, ICipherParameters parameters) =>
            new RsaPkcs1Wrapper(forWrapping, parameters);
    }

    internal class RsaOaepWrapper
        : IKeyWrapper, IKeyUnwrapper
    {
        private readonly AlgorithmIdentifier m_algID;
        private readonly IAsymmetricBlockCipher m_engine;

        public RsaOaepWrapper(bool forWrapping, ICipherParameters parameters, DerObjectIdentifier digestOid)
            : this(forWrapping, parameters, digestOid, digestOid)
        {
        }

        public RsaOaepWrapper(bool forWrapping, ICipherParameters parameters, DerObjectIdentifier digestOid,
            DerObjectIdentifier mgfOid)
        {
            AlgorithmIdentifier digestAlgID = new AlgorithmIdentifier(digestOid, DerNull.Instance);

            AlgorithmIdentifier mgfAlgID;
            if (mgfOid.Equals(NistObjectIdentifiers.IdShake128) || mgfOid.Equals(NistObjectIdentifiers.IdShake256))
            {
                mgfAlgID = new AlgorithmIdentifier(mgfOid);
            }
            else
            {
                mgfAlgID = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1,
                    new AlgorithmIdentifier(mgfOid, DerNull.Instance));
            }

            m_algID = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdRsaesOaep,
                new RsaesOaepParameters(digestAlgID, mgfAlgID));

            m_engine = new OaepEncoding(new RsaBlindedEngine(), DigestUtilities.GetDigest(digestOid),
                DigestUtilities.GetDigest(mgfOid), null);
            m_engine.Init(forWrapping, parameters);
        }

        public object AlgorithmDetails => m_algID;

        public IBlockResult Unwrap(byte[] cipherText, int offset, int length) =>
            new SimpleBlockResult(m_engine.ProcessBlock(cipherText, offset, length));

        public IBlockResult Wrap(byte[] keyData) =>
            new SimpleBlockResult(m_engine.ProcessBlock(keyData, 0, keyData.Length));
    }

    internal class RsaOaepWrapperProvider
        : WrapperProvider
    {
        private readonly DerObjectIdentifier m_digestOid;
        private readonly DerObjectIdentifier m_mgfOid;

        internal RsaOaepWrapperProvider(DerObjectIdentifier digestOid)
        {
            m_digestOid = digestOid;
            m_mgfOid = digestOid;
        }

        internal RsaOaepWrapperProvider(DerObjectIdentifier digestOid, DerObjectIdentifier mgfOid)
        {
            m_digestOid = digestOid;
            m_mgfOid = mgfOid;
        }

        object WrapperProvider.CreateWrapper(bool forWrapping, ICipherParameters parameters) =>
            new RsaOaepWrapper(forWrapping, parameters, m_digestOid, m_mgfOid);
    }
}
