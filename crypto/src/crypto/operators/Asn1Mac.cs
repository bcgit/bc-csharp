using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Operators
{

    public class DefaultMacStreamCalculator : IStreamCalculator
    {
        private readonly MacSink _stream;

        public DefaultMacStreamCalculator(IMac mac)
        {
            _stream = new MacSink(mac);
        }

        public void Init(KeyParameter key)
        {
            _stream.Mac.Init(key);
        }

        public Stream Stream
        {
            get { return _stream; }
        }
        public object GetResult()
        {
            byte[] res = new byte[_stream.Mac.GetMacSize()];
            _stream.Mac.DoFinal(res, 0);
            return res;
        }
    }


    public class DefaultMacAndDigestStreamCalculator : IStreamCalculator
    {

        private readonly MacSink macSink;
        private readonly DigestSink digestSink;
        private readonly Stream _stream;


        public DefaultMacAndDigestStreamCalculator(IMac imac, IDigest idigest)
        {
            this.macSink = new MacSink(imac);
            this.digestSink = new DigestSink(idigest);
            _stream = new MergedStream(macSink,digestSink);
        }


        public void Init(KeyParameter macKey)
        {
            this.macSink.Mac.Init(macKey);
        }

        public void Init(PbmParameter parameter, byte[] password)
        {

            byte[] pw = password;
            byte[] salt = parameter.Salt.GetOctets();
            byte[] K = new byte[pw.Length + salt.Length];

            System.Array.Copy(pw,K,pw.Length);
            System.Array.Copy(salt,0,K,pw.Length,salt.Length);
            int iter = parameter.IterationCount.Value.IntValue;
            this.digestSink.Digest.Reset();

            IDigest dig = DigestUtilities.GetDigest(digestSink.Digest.AlgorithmName);

           
        
            dig.BlockUpdate(K,0,K.Length);
            K = new byte[dig.GetDigestSize()];
            dig.DoFinal(K, 0);
            iter--;

            do
            {
                dig.BlockUpdate(K,0,K.Length);
                dig.DoFinal(K, 0);
            } while (--iter > 0);
        
           macSink.Mac.Init(new KeyParameter(K));
        }



        public Stream Stream
        {
            get { return _stream; }
        }


        public object GetResult()
        {
            byte[] macResult = new byte[macSink.Mac.GetMacSize()];
            macSink.Mac.DoFinal(macResult, 0);
            byte[] digestResult = new byte[digestSink.Digest.GetByteLength()];
            digestSink.Digest.DoFinal(digestResult, 0);
            return new DefaultMacAndDigestResult(digestResult, macResult);
        }

        private class MergedStream : Stream
        {

            private Stream aStream;
            private Stream bStream;

            public MergedStream(Stream aStream, Stream bStream)
            {
                this.aStream = aStream;
                this.bStream = bStream;
            }

            public override void Flush()
            {
                aStream.Flush();
                bStream.Flush();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                aStream.Seek(offset, origin);
                return bStream.Seek(offset, origin);
            }

            public override void SetLength(long value)
            {
                aStream.SetLength(value);
                bStream.SetLength(value);
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                aStream.Read(buffer, offset, count);
                return bStream.Read(buffer, offset, count);
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                aStream.Write(buffer, offset, count);
                bStream.Write(buffer, offset, count);
            }

            public override bool CanRead
            {
                get { return bStream.CanRead && aStream.CanRead; }
            }
            public override bool CanSeek
            {
                get { return bStream.CanSeek && aStream.CanSeek; }

            }
            public override bool CanWrite {
                get { return bStream.CanWrite && aStream.CanWrite; }
                
            }
            public override long Length {
                get
                {
                    return aStream.Length;              
                }
            }
            public override long Position
            {
                get { return aStream.Position; }

                set { aStream.Position = value; }
            }
        }
    }

    public struct DefaultMacAndDigestResult
    {
        public DefaultMacAndDigestResult(byte[] digestResult, byte[] macResult)
        {
            DigestResult = digestResult;
            MacResult = macResult;
        }

        public byte[] DigestResult { get; }

        public byte[] MacResult { get; }
    }

    public class Asn1MacFactory : IMacFactory
    {
        protected readonly AlgorithmIdentifier MacAlgorithmIdentifier;

        
   
        public Asn1MacFactory(AlgorithmIdentifier macAlgorithmIdentifier)
        {
            MacAlgorithmIdentifier = macAlgorithmIdentifier;  
        }

       

        public virtual object AlgorithmDetails
        {
            get { return MacAlgorithmIdentifier; }
        }

        public virtual IStreamCalculator CreateCalculator()
        {
           IMac mac = MacUtilities.GetMac(MacAlgorithmIdentifier.Algorithm);
           return new DefaultMacStreamCalculator(mac);
        }
    }


    public interface IMacFactoryProvider
    {
        IMacFactory CreateMacFactory(AlgorithmIdentifier algorithmIdentifier);
    }

    public class Asn1MacFactoryProvider : IMacFactoryProvider
    {
        public IMacFactory CreateMacFactory(AlgorithmIdentifier algorithmIdentifier)
        {
            return new Asn1MacFactory(algorithmIdentifier);
        }

        public IMacFactory CreateMacFactory(AlgorithmIdentifier digestAlgorithmIdentifier, AlgorithmIdentifier macAlgorithmIdentifier)
        {
            return new PkMacFactory(digestAlgorithmIdentifier,macAlgorithmIdentifier);
        }

        public IMacFactory CreateMacFactory(PbmParameter parameter)
        {
            return new PkMacFactory(parameter);
        }

    }



    public class PkMacFactory:Asn1MacFactory
    {
        private readonly AlgorithmIdentifier _digestAlgorithmIdentifier;
        private byte[] password;
        private int iterationCount;
        private byte[] salt;


     
        public PkMacFactory(SecureRandom random) : base(new AlgorithmIdentifier(IanaObjectIdentifiers.HmacSha1))
        {
            this._digestAlgorithmIdentifier = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
            this.iterationCount = 1000;
            this.salt = new byte[20];
            random.NextBytes(salt);        
        }

        public PkMacFactory(AlgorithmIdentifier digestAlgorithmIdentifier, AlgorithmIdentifier macAlgorithmIdentifier) : base(macAlgorithmIdentifier)
        {
            this._digestAlgorithmIdentifier = digestAlgorithmIdentifier;
        }

        public PkMacFactory(PbmParameter parameter):base(parameter.Mac)
        {
            this._digestAlgorithmIdentifier = parameter.Owf;         
            this.salt = parameter.Salt.GetOctets();
            this.iterationCount = parameter.IterationCount.Value.IntValue;           
        }

        public override object AlgorithmDetails
        {
            get
            {
                return new AlgorithmIdentifier(CmpObjectIdentifiers.passwordBasedMac,
                    new PbmParameter(salt, _digestAlgorithmIdentifier, iterationCount, MacAlgorithmIdentifier));
            }
        }


        public int IterationCount
        {
            set { this.iterationCount = value; }
        }
        public byte[] Salt
        {
            set { this.salt = value;}
        }
        public byte[] Password {
            set { this.password = value; }
        }
       

        public override IStreamCalculator CreateCalculator()
        {
           
            DefaultMacAndDigestStreamCalculator calc = new DefaultMacAndDigestStreamCalculator(
                MacUtilities.GetMac(this.MacAlgorithmIdentifier.Algorithm), 
                DigestUtilities.GetDigest(_digestAlgorithmIdentifier.Algorithm));
       
            PbmParameter parameter = new PbmParameter(salt, _digestAlgorithmIdentifier,iterationCount,MacAlgorithmIdentifier);                 
            calc.Init(parameter, password);
            
          
            return calc;
        }

    }


    public class MacVerifierFactory : IVerifierFactory
    {
        private readonly IMacFactory _macFactory;


        public MacVerifierFactory(IMacFactory macFactory)
        {
            this._macFactory = macFactory;
        }

        public object AlgorithmDetails
        {
            get { return _macFactory.AlgorithmDetails; }
        }
        public IStreamCalculator CreateCalculator()
        {
            return new MacVerifier(_macFactory.CreateCalculator());
        }

        private class MacVerifier : IStreamCalculator
        {
            public IStreamCalculator _calculator;

            public MacVerifier(IStreamCalculator calculator)
            {
                _calculator = calculator;
            }

            public Stream Stream
            {
                get { return _calculator.Stream; }
            }

            public object GetResult()
            {
                object result = _calculator.GetResult();
                if (result is byte[])
                {
                    return new DefaultMacVerifierResult((byte[])result);
                } else if (result is DefaultMacAndDigestResult)
                {
                    return new DefaultMacVerifierResult(((DefaultMacAndDigestResult)result).MacResult);

                }

                throw new InvalidOperationException("calculator did not return byte[] or DefaultMacVerifierResult");
            }
        }

    }


    public class DefaultMacVerifierResult:IVerifier
    {
        private readonly byte[] _calculatedResult;

        public DefaultMacVerifierResult(byte[] calculatedResult)
        {
            this._calculatedResult = calculatedResult;
        }


        public bool IsVerified(byte[] data)
        {
            return Arrays.ConstantTimeAreEqual(_calculatedResult, data);
        }

        public bool IsVerified(byte[] source, int off, int length)
        {
            if (_calculatedResult.Length != length)
            {
                return false;
            }

            //
            // Must be constant time.
            //
            int j = 0;        
            int nonEqual = 0;        
            for (int i = off; i < off + length; i++)
            {
                nonEqual |= (_calculatedResult[j++] ^ source[i]);
            }

            return nonEqual == 0;
        }
    }


}
