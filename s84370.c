/*
 * compile and run with:
 *	make
 *	make run
 */
#include <stdio.h>
#include <openssl/evp.h>
#include <ctype.h>              /* isalnum */
#include <fcntl.h>              /* O_RDONLY */
#include <stdio.h>              /* fopen */
#include <unistd.h>             /* read */
#include <openssl/pem.h>        /* PEM_read_PUBKEY */
#include <openssl/err.h>        /* ERR_load_crypto_strings */
#include <string.h>
/*
 * decrypts a message using AES-256-CFB
 */
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
		            unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
        int len;
	int plaintext_len;

	/* Create and initialise the context */
	ctx = EVP_CIPHER_CTX_new();

	/*
	 * Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb128(), NULL, key, iv);
	
	/*
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary.
	 */
	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
					        
	plaintext_len = len;

	/*
	 * Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}
/*
 * determines the longest word in a given text
 */
void find_longest_word(unsigned char *string, int length, int *word_index, int *word_length){
	int count,i, index, max;
	index = max = count = 0;
 	/* Finding length of longest word and starting index */
 	for( i = 0 ; i< length ; i++)
 	{		
		if(strchr("\n- ,.»«–!?=:;", string[i]) == NULL)
  		{
   			count++;
  		}
  		else
  		{
   			if(count > max)
   			{
    				max = count;
    				index = i-max;
   			}
   			count = 0;
  		}
 	}
 	/* Checking if last word is longest */
 	if(count>max)
 	{
  		max = count;
  		index = length-max;
 	}
	*word_index = index;
	*word_length = max;
}
/*
 * marks a specified word with * before and after
 */
void mark_a_word(unsigned char *plaintext, int index, int max, unsigned char *buffer, int buffer_size){
  	int x = 0;
	max++;
  	for(int i = 0; i < buffer_size; i++) {
    		if(i != index && i != index + max){
			unsigned char temp = plaintext[i-x];
    			buffer[i] = temp;
		}
		else{
			buffer[i] = '*';
			x++;
		}
  	} 
}
/*
 * reads in the public key
 */
EVP_PKEY* read_public_key(){
	FILE *keyfp;
	EVP_PKEY *pubkey = NULL;
	keyfp = fopen("rsapub.pem", "r");
        pubkey = PEM_read_PUBKEY(keyfp, NULL, NULL, NULL);
	return pubkey;
}
/*
 * stores a message to a file
 */
void save_to_bin_file(unsigned char *content, int size){
	FILE *fh = fopen ("s84370-result.bin", "wb");
    	if (fh != NULL) {
        	fwrite(content, 1, size, fh);		
    	}
	fclose (fh);
}

void print_marked_text(unsigned char *text, int size){
	printf("Here is the marked text:\n");
        for(int i = 0; i<size; i++)
                printf("%c", text[i]);
        printf("\n");
}

int main()
{
	/*
	 * open and read encrypted bin file into buffer
	 * */
	int buffer_size = 1269; //found out file size with stat command
	unsigned char text_buffer[buffer_size];
	FILE *ptr;
	ptr = fopen("s84370-cipher.bin","rb");  // r for read, b for binary
	fread(text_buffer,sizeof(text_buffer),1,ptr); // read bytes to our buffer
	/*
	 *determine encryption type and length
	 */
	const EVP_CIPHER *encryption_type;
	int key_length, iv_length;
	encryption_type = EVP_aes_256_cfb128();
	key_length = EVP_CIPHER_key_length(encryption_type);
	iv_length = EVP_CIPHER_iv_length(encryption_type);
	/*
	 * Read key and initialisation vector from bin file
	 */	
	unsigned char key_buffer[key_length];
	unsigned char iv_buffer[iv_length];
	ptr = fopen("s84370-key.bin","rb");
        fread(key_buffer,sizeof(key_buffer),1,ptr);
	fread(iv_buffer,sizeof(iv_buffer),1,ptr);
	/*
	 * decrypt the text into plain text
	 */
	unsigned char plaintext[buffer_size];
	decrypt(text_buffer, buffer_size, key_buffer, iv_buffer, plaintext);
	/*
	 * get longest word
	 */
	int index = 0, max = 0;
	find_longest_word(plaintext, sizeof(plaintext), &index, &max);
	/*
	 * mark the longest word in text
	 */
	unsigned char edited_text[sizeof(plaintext)+2];
	mark_a_word(plaintext, index, max, edited_text, sizeof(edited_text));
	/*
         * outputs the marked text
         */
	print_marked_text(edited_text, sizeof(edited_text));
	/*
	 * encrypt the edited text
	 */
	unsigned char *out;
	EVP_PKEY *pubkey = read_public_key();
        EVP_PKEY_CTX *ctx;
        size_t outlen;
        ctx = EVP_PKEY_CTX_new(pubkey, NULL);
        if(EVP_PKEY_encrypt_init(ctx)<=0)
                printf("%s", "Encryption init has failed");
        if (!ctx)
                printf("%s", "Context creation has failed");
        /*if(EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_OAEP_PADDING)<=0)
                printf("%s", "RSA padding has failed");*/
        /*
         * determines the output length
         */
        if(EVP_PKEY_encrypt(ctx, NULL, &outlen, edited_text, sizeof(edited_text))<=0)
                printf("%s", "Encryption mesuring has failed");
	/*
         * allocated memory
         */
        out = OPENSSL_malloc(outlen);
        if (!out)
                printf("%s", "SSLmalloc has failed");
        /*
         * writes to out variable
         */
        if(EVP_PKEY_encrypt(ctx, out, &outlen, edited_text, sizeof(edited_text))<=0)
                printf("%s", "Encryption writing has failed");
        /*
         * clean up
         */
	EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
	/*
	 * save encrypted text to file
	 */
	save_to_bin_file(out, outlen);
	/*
	 * If the following line causes the error message
	 * 	undefined reference to 'EVP_idea_ecb',
	 * please check the SSLDIR that is set in the Makefile.
	 */
	EVP_idea_ecb();
	return 0;
}
