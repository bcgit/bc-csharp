using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Crmf
{

//    public delegate IBlockCipher BlockCipherCreator(ICipherParameters);
//
//    public class EncryptedValueBuilder
//    {
//        private readonly IBlockCipher _cipher;
//        private static readonly IDictionary algToDelegate = Platform.CreateHashtable();
//        static EncryptedValueBuilder()
//        {
//            algToDelegate[NistObjectIdentifiers.IdAes128Cbc] = new CipherCreator()
//                {Creator = delegate(ICipherParameters param) { return new AesEngine(); }};
//
//        }
//
//
//        public EncryptedValueBuilder(DerObjectIdentifier alg)
//        {
//            
//        }
//
//
//        private static IBlockCipher AesCBC(ICipherParameters param)
//        {
//            if (param is ParametersWithIV ivParam) {
//                return new 
//            }
//            else
//            {
//                throw new ArgumentException("expecting param to be ParametersWithIv");
//            }
//        }
//
//
//
//        private class CipherCreator
//        {
//            public BlockCipherCreator Creator { get; set; }
//        }
//
//    }
}
