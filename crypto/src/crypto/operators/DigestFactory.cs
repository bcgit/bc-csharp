using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Tests;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;

namespace Org.BouncyCastle.Crypto.Operators
{



    public class DigestFactory : IDigestFactory
    {

        public static DigestFactory Get(DerObjectIdentifier oid)
        {
            return new DigestFactory(DigestUtilities.GetDigest(oid), oid);          
        }

        public static DigestFactory Get(String mechanism)
        {
            DerObjectIdentifier oid = DigestUtilities.GetObjectIdentifier(mechanism);
            return new DigestFactory(DigestUtilities.GetDigest(oid), oid);
        }


        private IDigest digest;
        private DerObjectIdentifier oid;

        public DigestFactory(IDigest digest, DerObjectIdentifier oid)
        {
            this.digest = digest;
            this.oid = oid;
        }    

        public object AlgorithmDetails => new AlgorithmIdentifier(oid);

        public int DigestLength => digest.GetDigestSize();

        public IStreamCalculator CreateCalculator() => new DfDigestStream(digest);
        
    }


    internal class DfDigestStream : IStreamCalculator
    {

        private DigestSink stream;

        public DfDigestStream(IDigest digest)
        {          
            stream = new DigestSink(digest);
        }

        public Stream Stream => stream;

        public object GetResult()
        {
            byte[] result = new byte[stream.Digest.GetDigestSize()];
            stream.Digest.DoFinal(result, 0);
            return new SimpleBlockResult(result);
        }
      
    }

   

}
