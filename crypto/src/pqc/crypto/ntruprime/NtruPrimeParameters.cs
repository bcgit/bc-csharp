using System;
using System.ComponentModel;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Modes;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    public class NtruPrimeParameters : ICipherParameters
    {

        private String name;
        private int p;
        private int q;
        private int _roundedBytes;
        private bool LPR;
        private int _w;
        private int _rqBytes;
        private int _tau0;
        private int _tau1;
        private int _tau2;
        private int _tau3;
        private int _skBytes;
        private int _pkBytes;
        private int _ctBytes;
        private NtruPrimeEngine _pEngine;
        
        public NtruPrimeParameters(String name, int p, int q, bool LPR, int w, int tau0,
            int tau1, int tau2, int tau3, int skBytes, int pkBytes, int ctBytes, int roundedBytes, int rqBytes)
        {
            this.name = name;
            this.p = p;
            this.q = q;
            this.LPR = LPR;
            this._w = w;
            this._tau0 = tau0;
            this._tau1 = tau1;
            this._tau2 = tau2;
            this._tau3 = tau3;
            
            // KEM Parameters
            this._roundedBytes = roundedBytes;
            this._rqBytes = rqBytes;
            this._skBytes = skBytes;
            this._pkBytes = pkBytes;
            this._ctBytes = ctBytes;
            this._pEngine = new NtruPrimeEngine(p,q, LPR, w, tau0, tau1, tau2, tau3, skBytes, pkBytes, ctBytes, roundedBytes, rqBytes);
        }

        public static NtruPrimeParameters ntrulpr653 = new NtruPrimeParameters("NTRU_LPRime_653", 653, 4621, true, 252, 2175,113,2031,290,1125,897,1025, 865, -1);
        public static NtruPrimeParameters ntrulpr761 = new NtruPrimeParameters("NTRU_LPRime_761", 761, 4591, true, 250, 2156,114,2007,287,1294,1039,1167, 1007, -1);
        public static NtruPrimeParameters ntrulpr857 = new NtruPrimeParameters("NTRU_LPRime_857", 857, 5167, true, 281, 2433,101,2265,324,1463,1184,1312, 1152, -1);
        public static NtruPrimeParameters ntrulpr953 = new NtruPrimeParameters("NTRU_LPRime_953", 953, 6343, true, 345, 2997,82,2798,400,1652,1349,1477, 1317, -1);
        public static NtruPrimeParameters ntrulpr1013 = new NtruPrimeParameters("NTRU_LPRime_1013", 1013, 7177, true, 392, 3367,73,3143,449,1773,1455,1583, 1423, -1);
        public static NtruPrimeParameters ntrulpr1277 = new NtruPrimeParameters("NTRU_LPRime_1277", 1277, 7879, true, 429, 3724,66,3469,496,2231,1847,1975, 1815, -1);
        
        public static NtruPrimeParameters sntrup653 = new NtruPrimeParameters("SNTRU_Prime_653", 653, 4621, false, 288, -1,-1,-1,-1,1518,994,897, 865, 994);
        public static NtruPrimeParameters sntrup761 = new NtruPrimeParameters("SNTRU_Prime_761", 761, 4591, false, 286, -1,-1,-1,-1,1763,1158,1039, 1007, 1158);
        public static NtruPrimeParameters sntrup857 = new NtruPrimeParameters("SNTRU_Prime_857", 857, 5167, false, 322, -1,-1,-1,-1,1999,1322,1184, 1152, 1322);
        public static NtruPrimeParameters sntrup953 = new NtruPrimeParameters("SNTRU_Prime_953", 953, 6343, false, 396, -1,-1,-1,-1,2254,1505,1349, 1317, 1505);
        public static NtruPrimeParameters sntrup1013 = new NtruPrimeParameters("SNTRU_Prime_1013", 1013, 7177, false, 448, -1,-1,-1,-1,2417,1623,1455, 1423, 1623);
        public static NtruPrimeParameters sntrup1277 = new NtruPrimeParameters("SNTRU_Prime_1277", 1277, 7879, false, 492, -1,-1,-1,-1,3059,2067,1847, 1815, 2067);
        
        public int P => p;
        public bool lpr => LPR;
        
        public int Q => q;

        internal NtruPrimeEngine PEngine => _pEngine;

    }
}
