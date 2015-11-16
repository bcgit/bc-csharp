using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Crypto.Prng.Test
{
    public class DRBGTestVector
    {
        private IDigest _digest;
        private IBlockCipher _cipher;
        private int _keySizeInBits;
        private IEntropySource _eSource;
        private bool _pr;
        private String _nonce;
        private String _personalisation;
        private int _ss;
        private String[] _ev;
        private List<string> _ai = new List<string>();

        public DRBGTestVector(IDigest digest, IEntropySource eSource, bool predictionResistance, String nonce, int securityStrength, String[] expected)
        {
            _digest = digest;
            _eSource = eSource;
            _pr = predictionResistance;
            _nonce = nonce;
            _ss = securityStrength;
            _ev = expected;
            _personalisation = null;
        }

        public DRBGTestVector(IBlockCipher cipher, int keySizeInBits, IEntropySource eSource, bool predictionResistance, String nonce, int securityStrength, String[] expected)
        {
            _cipher = cipher;
            _keySizeInBits = keySizeInBits;
            _eSource = eSource;
            _pr = predictionResistance;
            _nonce = nonce;
            _ss = securityStrength;
            _ev = expected;
            _personalisation = null;
        }

        public IDigest getDigest()
        {
            return _digest;
        }

        public IBlockCipher getCipher()
        {
            return _cipher;
        }

        public int keySizeInBits()
        {
            return _keySizeInBits;
        }

        public DRBGTestVector addAdditionalInput(String input)
        {
            _ai.Add(input);

            return this;
        }

        public DRBGTestVector setPersonalizationString(String p)
        {
            _personalisation = p;

            return this;
        }

        public IEntropySource entropySource()
        {
            return _eSource;
        }

        public bool predictionResistance()
        {
            return _pr;
        }

        public byte[] nonce()
        {
            if (_nonce == null)
            {
                return null;
            }

            return Hex.Decode(_nonce);
        }

        public byte[] personalizationString()
        {
            if (_personalisation == null)
            {
                return null;
            }

            return Hex.Decode(_personalisation);
        }

        public int securityStrength()
        {
            return _ss;
        }

        public byte[] expectedValue(int index)
        {
            return Hex.Decode(_ev[index]);
        }

        public byte[] additionalInput(int position)
        {
            int len = _ai.Count;
            byte[] rv;
            if (position >= len)
            {
                rv = null;
            }
            else
            {
                rv = Hex.Decode((string)(_ai[position]));
            }
            return rv;
        }

    }
}
