using System;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    abstract internal class LowmcConstants
    {
        internal uint[] linearMatrices;
        internal uint[] roundConstants;
        internal uint[] keyMatrices;

        internal KMatrices _LMatrix;
        internal KMatrices _KMatrix;
        internal KMatrices RConstants;
        
        internal uint[] linearMatrices_full;
        internal uint[] keyMatrices_full;
        internal uint[] keyMatrices_inv;
        internal uint[] linearMatrices_inv;
        internal uint[] roundConstants_full;

        internal KMatrices LMatrix_full;
        internal KMatrices LMatrix_inv;
        internal KMatrices KMatrix_full;
        internal KMatrices KMatrix_inv;
        internal KMatrices RConstants_full;

        internal static uint[] ReadFromProperty(uint[] data, int intSize)
        {
            uint[] ints = new uint[intSize];
            Array.Copy(data, ints, data.Length);
            return ints;
        }

    
    
        // Functions to return individual matricies and round constants

        /* Return a pointer to the r-th matrix. The caller must know the dimensions */
        private KMatricesWithPointer GET_MAT(KMatrices m, int r)
        {
            KMatricesWithPointer mwp = new KMatricesWithPointer(m);
            mwp.SetMatrixPointer(r*mwp.GetSize());
            return mwp;
        }


        /* Return the LowMC linear matrix for this round */
        internal KMatricesWithPointer LMatrix(PicnicEngine engine, int round)
        {

            if(engine.stateSizeBits == 128)
            {
                return GET_MAT(_LMatrix, round);
            }
            else if(engine.stateSizeBits == 129)
            {
                return GET_MAT(LMatrix_full, round);
            }
            else if(engine.stateSizeBits == 192)
            {
                if(engine.numRounds == 4)
                {
                    return GET_MAT(LMatrix_full, round);
                }
                else
                {
                    return GET_MAT(_LMatrix, round);
                }
            }
            else if(engine.stateSizeBits == 255)
            {
                return GET_MAT(LMatrix_full, round);
            }
            else if(engine.stateSizeBits == 256)
            {
                return GET_MAT(_LMatrix, round);
            }
            else
            {
                return null;
            }
        }

        /* Return the LowMC inverse linear layer matrix for this round */
        internal KMatricesWithPointer LMatrixInv(PicnicEngine engine, int round)
        {
            if(engine.stateSizeBits == 129)
            {
                return GET_MAT(LMatrix_inv, round);
            }
            else if(engine.stateSizeBits == 192 && engine.numRounds == 4)
            {
                return GET_MAT(LMatrix_inv, round);
            }
            else if(engine.stateSizeBits == 255)
            {
                return GET_MAT(LMatrix_inv, round);
            }
            else
            {
                return null;
            }
        }

        /* Return the LowMC key matrix for this round */
        internal KMatricesWithPointer KMatrix(PicnicEngine engine, int round)
        {
            if(engine.stateSizeBits == 128)
            {
                return GET_MAT(_KMatrix, round);
            }
            else if(engine.stateSizeBits == 129)
            {
                return GET_MAT(KMatrix_full, round);
            }
            else if(engine.stateSizeBits == 192)
            {
                if(engine.numRounds == 4)
                {
                    return GET_MAT(KMatrix_full, round);
                }
                else
                {
                    return GET_MAT(_KMatrix, round);
                }
            }
            else if(engine.stateSizeBits == 255)
            {
                return GET_MAT(KMatrix_full, round);
            }
            else if(engine.stateSizeBits == 256)
            {
                return GET_MAT(_KMatrix, round);
            }
            else
            {
                return null;
            }
        }

        /* Return the LowMC inverse key matrix for this round */
        internal KMatricesWithPointer KMatrixInv(PicnicEngine engine, int round)
        {
            if(engine.stateSizeBits == 129)
            {
                return GET_MAT(KMatrix_inv, round);
            }
            else if(engine.stateSizeBits == 192 && engine.numRounds == 4)
            {
                return GET_MAT(KMatrix_inv, round);
            }
            else if(engine.stateSizeBits == 255)
            {
                return GET_MAT(KMatrix_inv, round);
            }
            else
            {
                return null;
            }
        }


        /* Return the LowMC round constant for this round */
        internal KMatricesWithPointer RConstant(PicnicEngine engine, int round)
        {
            if(engine.stateSizeBits == 128)
            {
                return GET_MAT(RConstants, round);
            }
            else if(engine.stateSizeBits == 129)
            {
                return GET_MAT(RConstants_full, round);
            }
            else if(engine.stateSizeBits == 192)
            {
                if(engine.numRounds == 4)
                {
                    return GET_MAT(RConstants_full, round);
                }
                else
                {
                    return GET_MAT(RConstants, round);
                }
            }
            else if(engine.stateSizeBits == 255)
            {
                return GET_MAT(RConstants_full, round);
            }
            else if(engine.stateSizeBits == 256)
            {
                return GET_MAT(RConstants, round);
            }
            else
            {
                return null;
            }
        }
    }
}
