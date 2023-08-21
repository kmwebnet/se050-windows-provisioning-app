/*
 *
 * Copyright 2023 kmwebnet
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @par Description
 * NXP SE050 Windows FT260 i2c code
 * @par History
 *
 **/
#include <windows.h> 
#include "i2c_a7.h"
#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

#include "LibFT260.h" 
#include "se050.h"
#define MASK_1 0x0f  
#define VID 0x0403
#define PID 0x6030

/**
* Opens the communication channel to I2C device
*/
extern "C" i2c_error_t axI2CInit(void** conn_ctx, const char* pDevName)
{
    AX_UNUSED_ARG(pDevName);
    FT260_STATUS ftStatus = FT260_OTHER_ERROR;
    FT260_HANDLE ft260Handle = INVALID_HANDLE_VALUE;

    LOG_D("I2CInit: opening \n");

    // Open device
    ftStatus = FT260_OpenByVidPid(VID, PID, 0, &ft260Handle);
    if (FT260_OK != ftStatus) {
        LOG_E("Open device Failed, status: %d\n", ftStatus);
        return I2C_FAILED;
    }

    //    Initialize as an I2C master, and read/write data to an I2C slave
    ftStatus = FT260_I2CMaster_Init(ft260Handle, 3400);
    if (FT260_OK != ftStatus)
    {
        LOG_E("I2C init Failed, status: %d\n", ftStatus);
        return I2C_FAILED;
    }

    *conn_ctx = malloc(sizeof(FT260_HANDLE));
    if(*conn_ctx == NULL)
    {
        LOG_E("I2C driver: Memory allocation failed!\n");
        FT260_Close(ft260Handle);
        return I2C_FAILED;
    }
    else{
        *(FT260_HANDLE*)(*conn_ctx) = ft260Handle;
        return I2C_OK;
    }
}

/**
* Closes the communication channel to I2C device
*/
extern "C" void axI2CTerm(void* conn_ctx, int mode)
{
    FT260_STATUS ftStatus = FT260_OTHER_ERROR;
    AX_UNUSED_ARG(mode);
    // printf("axI2CTerm (enter) i2c device =  %d\n", *(int*)(conn_ctx));
    if (conn_ctx != NULL) {
        if (FT260_Close(*(FT260_HANDLE*)(conn_ctx)) != FT260_OK) {
            LOG_E("Failed to close i2c device %d.\n", *(int*)(conn_ctx));
        }
        else {
            LOG_D("Close i2c device %d.\n", *(int*)(conn_ctx));
        }
        free(conn_ctx);
    }
    // printf("axI2CTerm (exit)\n");
    return;
}

#if defined(SCI2C)
/**
 * Write a single byte to the slave device.
 * In the context of the SCI2C protocol, this command is only invoked
 * to trigger a wake-up of the attached secure module. As such this
 * wakeup command 'wakes' the device, but does not receive a valid response.
 * \note \par bus is currently not used to distinguish between I2C masters.
*/
i2c_error_t axI2CWriteByte(void* conn_ctx, unsigned char bus, unsigned char addr, unsigned char * pTx)
{
    int nrWritten = -1;
    i2c_error_t rv;
    int axSmDevice = *(int*)conn_ctx;

    if (bus != I2C_BUS_0)
    {
        LOG_E("axI2CWriteByte on wrong bus %x (addr %x)\n", bus, addr);
    }

    nrWritten = write(axSmDevice, pTx, 1);
    if (nrWritten < 0)
    {
        // I2C_LOG_PRINTF("Failed writing data (nrWritten=%d).\n", nrWritten);
        rv = I2C_FAILED;
    }
    else
    {
        if (nrWritten == 1)
        {
            rv = I2C_OK;
        }
        else
        {
            rv = I2C_FAILED;
        }
    }

    return rv;
}
#endif // defined(SCI2C)

#if defined(SCI2C) || defined(T1oI2C)
extern "C" i2c_error_t axI2CWrite(void* conn_ctx, unsigned char bus, unsigned char addr, unsigned char * pTx, unsigned short txLen)
{
    AX_UNUSED_ARG(bus);
    DWORD nrWritten = 0;
    i2c_error_t rv;
    FT260_STATUS ftStatus = FT260_OTHER_ERROR;
    FT260_HANDLE ft260Handle = *(FT260_HANDLE*)conn_ctx;
#ifdef LOG_I2C
    int i = 0;
#endif

    if(pTx == NULL || txLen > MAX_DATA_LEN)
    {
        return I2C_FAILED;
    }

    LOG_MAU8_D("TX (axI2CWrite) > ",pTx,txLen);
    unsigned char addap = addr >> 1;
    ftStatus = FT260_I2CMaster_Write(ft260Handle, addap, FT260_I2C_START_AND_STOP, pTx, txLen, &nrWritten);
    if (FT260_OK != ftStatus)
    {
        LOG_E("FT260_I2CMaster_Write Failed, status: %d\n", ftStatus);
        return I2C_FAILED;
    }

    if (nrWritten == 0)
    {
       LOG_E("Failed writing data (nrWritten=%d).\n", nrWritten);
       rv = I2C_FAILED;
    }
    else
    {
        if (nrWritten == txLen) // okay
        {
            rv = I2C_OK;
        }
        else
        {
            rv = I2C_FAILED;
        }
    }
    LOG_D("Done with rv = %02x ", rv);

    return rv;
}
#endif // defined(SCI2C) || defined(T1oI2C)

#ifdef T1oI2C
extern "C" i2c_error_t axI2CRead(void* conn_ctx, unsigned char bus, unsigned char addr, unsigned char * pRx, unsigned short rxLen)
{
    AX_UNUSED_ARG(bus);
    DWORD nrRead = 0;
    i2c_error_t rv;
    FT260_STATUS ftStatus = FT260_OTHER_ERROR;
    FT260_HANDLE ft260Handle = *(FT260_HANDLE*)conn_ctx;

    if(pRx == NULL || rxLen > MAX_DATA_LEN)
    {
        return I2C_FAILED;
    }

    unsigned char addap = addr >> 1;
    ftStatus = FT260_I2CMaster_Read(ft260Handle, addap, FT260_I2C_START_AND_STOP, pRx, rxLen, &nrRead, 5000);
    if (FT260_OK != ftStatus)
    {
        LOG_E("FT260_I2CMaster_Read Failed, status: %d\n", ftStatus);

        if (FT260_I2C_READ_FAIL == ftStatus)
        {
            LOG_E("FT260_I2C_READ_FAIL\n");
		}


        return I2C_FAILED;
    }

   if (nrRead == 0)
   {
      LOG_E("Failed Read data (nrRead=%d).\n", nrRead);
      rv = I2C_FAILED;
   }
   else
   {
        if (nrRead == rxLen) // okay
        {
            rv = I2C_OK;
        }
        else
        {
            rv = I2C_FAILED;
        }
   }
    LOG_D("Done with rv = %02x ", rv);
    LOG_MAU8_D("TX (axI2CRead): ",pRx,rxLen);
    return rv;
}
#endif // T1oI2C
