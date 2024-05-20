using System;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    internal abstract class LowmcConstants
    {
        internal KMatrices _LMatrix;
        internal KMatrices _KMatrix;
        internal KMatrices RConstants;

        internal KMatrices LMatrix_full;
        internal KMatrices LMatrix_inv;
        internal KMatrices KMatrix_full;
        internal KMatrices KMatrix_inv;
        internal KMatrices RConstants_full;

        /// <summary>Return a pointer to the r-th matrix.</summary>
        /// <remarks>The caller must know the dimensions.</remarks>
        private KMatricesWithPointer GET_MAT(KMatrices m, int r)
        {
            KMatricesWithPointer mwp = new KMatricesWithPointer(m);
            mwp.SetMatrixPointer(r * mwp.GetSize());
            return mwp;
        }

        /// <summary>Return the LowMC linear matrix for this round.</summary>
        internal KMatricesWithPointer LMatrix(PicnicEngine engine, int round)
        {
            switch (engine.stateSizeBits)
            {
            case 128:
            case 256:
                return GET_MAT(_LMatrix, round);
            case 129:
            case 255:
                return GET_MAT(LMatrix_full, round);
            case 192:
                return GET_MAT(engine.numRounds == 4 ? LMatrix_full : _LMatrix, round);
            default:
                return null;
            }
        }

        /// <summary>Return the LowMC inverse linear layer matrix for this round.</summary>
        internal KMatricesWithPointer LMatrixInv(PicnicEngine engine, int round)
        {
            switch (engine.stateSizeBits)
            {
            case 129:
            case 255:
                return GET_MAT(LMatrix_inv, round);
            case 192:
                return engine.numRounds == 4 ? GET_MAT(LMatrix_inv, round) : null;
            default:
                return null;
            }
        }

        /// <summary>Return the LowMC key matrix for this round.</summary>
        internal KMatricesWithPointer KMatrix(PicnicEngine engine, int round)
        {
            switch (engine.stateSizeBits)
            {
            case 128:
            case 256:
                return GET_MAT(_KMatrix, round);
            case 129:
            case 255:
                return GET_MAT(KMatrix_full, round);
            case 192:
                return GET_MAT(engine.numRounds == 4 ? KMatrix_full : _KMatrix, round);
            default:
                return null;
            }
        }

        /// <summary>Return the LowMC inverse key matrix for this round.</summary>
        internal KMatricesWithPointer KMatrixInv(PicnicEngine engine, int round)
        {
            switch (engine.stateSizeBits)
            {
            case 129:
            case 255:
                return GET_MAT(KMatrix_inv, round);
            case 192:
                return engine.numRounds == 4 ? GET_MAT(KMatrix_inv, round) : null;
            default:
                return null;
            }
        }

        /// <summary>Return the LowMC round constant for this round.</summary>
        internal KMatricesWithPointer RConstant(PicnicEngine engine, int round)
        {
            switch (engine.stateSizeBits)
            {
            case 128:
            case 256:
                return GET_MAT(RConstants, round);
            case 129:
            case 255:
                return GET_MAT(RConstants_full, round);
            case 192:
                return GET_MAT(engine.numRounds == 4 ? RConstants_full : RConstants, round);
            default:
                return null;
            }
        }
    }
}
