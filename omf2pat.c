/* a omf51 libary parser
   The parser automatically handles OMF2 which is found in Keil (16 bit index)
   and just parses the records public, code and fixup which are important for
   creating IDA pat files. All other records may be listet or simply ignored
    
*/
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define MAXCONTENT   0x2000   // one lib module can hold 8k enough?
#define MAXNAMESIZE      40   // should be 40
#define MAXPUBLIC        10   // have not found more than 4 public code entries up to now

typedef struct _OMFREC
{
  unsigned char  Typ;
  unsigned short Len;
  unsigned char  Content[MAXCONTENT]; 
}tOmfRec;

typedef struct _PUBLIC
{
  unsigned short Offset;
  unsigned char  PubName[MAXNAMESIZE];
}tPublic;


typedef struct _PATREC
{
   unsigned short numPublics;
   tPublic        PubEntries[MAXPUBLIC]; 
   unsigned short CodeLen;
   unsigned short Fixup;
   unsigned char  Code[MAXCONTENT*2];
}tPatRec;


typedef struct _LIBHEADER
{
   unsigned short ModulCount;
   unsigned short BlockNum;
   unsigned char  ByteNum; 
}tLibHeader;

// global vars
tPatRec   PatRecord;
FILE     *infile;
FILE     *outfile; 
unsigned  OptCode;
unsigned  OptDebug;
unsigned  NumRecords;

//clear the global record
void InitPatRecord(void)
{
   memset (&PatRecord,0,sizeof(PatRecord));
   memset (PatRecord.Code,'.',sizeof(PatRecord.Code));//maybe remove this
}

//sort the puplics by offset not very fancy but working 
void SortPuplics(void)
{
   int i,j;
   tPublic tmp;
   
   for (j=0; j < PatRecord.numPublics ; j++)
   {
      for (i=0; i < PatRecord.numPublics ; i++)
      {
         if (PatRecord.PubEntries[i].Offset > PatRecord.PubEntries[i+1].Offset)
         { 
            tmp = PatRecord.PubEntries[i];
            PatRecord.PubEntries[i]   = PatRecord.PubEntries[i+1];
            PatRecord.PubEntries[i+1] = tmp;     
         }     
      } 
      PatRecord.PubEntries[PatRecord.numPublics-1] = PatRecord.PubEntries[PatRecord.numPublics];
      memset (&PatRecord.PubEntries[PatRecord.numPublics],0,sizeof(tPublic)); 
   }
}

// init the name string  with space and limit the size 
// to MAXNAMESIZE copy the string fron src to dest 
void InitNameString(char *dest,char *src, unsigned char len)
{
   memset(dest,' ',MAXNAMESIZE);
   len =  (len <= MAXNAMESIZE) ? len : MAXNAMESIZE;
   memcpy(dest,src,len);
   dest[MAXNAMESIZE]= '\0'; 
}

// read a OMF record from a file stream into omf 
// it handles the checksum 
// return: number of bytes valid in the record 
int ReadOmfRec(FILE *file, tOmfRec *omf) 
{
   unsigned char chk;
   int i; 

   if (feof(file)) 
   {
      printf("file ends!\n");
      exit(0);
   }  
   fread(&omf->Typ,1,1,file);
   fread(&omf->Len,2,1,file);
   // todo check for overflows
   if(omf->Len >= MAXCONTENT)
   {
      printf("Error: Record overflow try to change MAXCONTENT\n");
      exit(-1);
   }  
   
   fread(&omf->Content,1,omf->Len,file);
                   
   chk= omf->Typ; chk+= omf->Len & 0xFF; chk+= omf->Len >> 8;
   for (i=0;i < omf->Len;i++) chk+=omf->Content[i];
      
   if (chk != 0)
   {   
      printf("Error: Checksum wrong\n");
      exit(-2);
   }
   return omf->Len;   
}

void DebugInfo(tOmfRec *omf)
{
   int i;
   printf("  ");
   for (i=0;i < omf->Len;i++)
   {
      printf("%02X",omf->Content[i]); 
   } 
   printf("\n");
}

void SegmentInfo(tOmfRec *omf)
{
   char s[255];
   unsigned short sid;
   unsigned char  sinfo;
   unsigned char  styp;
   unsigned char  res;
   unsigned short sbase;
   unsigned short ssize;
   
   unsigned char  slen;
   unsigned size    = omf->Len-1; // -chk
   unsigned char *p = &omf->Content[0];
   if(OptDebug)
   {	
      printf("   Seg : +----------------------------------------+----+---+---+----+----+\n");
      printf("         |                                        |sidx|nfo|typ|base|size|\n");
   }
   while (size)
   {
      sid = *p++; size --;
      if (omf->Typ & 0x01)//OMF2
      {
         sid = sid + *p++ *256; size --; 
      }
      sinfo = *p++; size--;
      styp  = *p++; size--;
      res   = *p++; size--;
      sbase = *p++; sbase += *p++ * 256; size -=2;
      ssize = *p++; ssize += *p++ * 256; size -=2;
      slen  = *p++;                      size --;
      InitNameString(s,p,slen); 
      size -= slen;
      p    += slen;
      if(OptDebug)
        printf("         |%s|%04X|%02X |%02X |%04X|%04X|\n",s,sid,sinfo,styp,sbase,ssize);
   }
   if(OptDebug)
     printf("         +----------------------------------------+----+---+---+----+----+\n");    
}

void HeaderInfo(tOmfRec *omf)
{
   char s[255];
   unsigned char  inf;
   unsigned char  slen;
   
   //unsigned size    = omf->Len-1; // -chk
   unsigned char *p = &omf->Content[0];
   if(OptDebug)
   {
      printf("   Hdr : +----------------------------------------+---+\n");
      printf("         |                                        |inf|\n");
   }
   inf = *p++; //size--;
   slen= *p++; //size --;
   InitNameString(s,p,slen); 
   //size -= slen;
   if(OptDebug)
   {	
     printf("         |%s|%02X |\n",s,inf); 
     printf("         +----------------------------------------+---+\n");      
   }
}

void RegMaskInfo(tOmfRec *omf)
{
   char s[255];
   unsigned char  typ;
   unsigned short mask;
   unsigned char  slen;
   
   unsigned size    = omf->Len-1; // -chk
   unsigned char *p = &omf->Content[0];
   if(OptDebug)
   {
      printf("   Reg : +----------------------------------------+---+----+\n");
      printf("         |                                        |typ|mask|\n");
   }
   while (size)
   {
      typ  = *p++; size --;
      mask = *p++; size --;
      mask = mask + *p++ *256; size --;
      slen= *p++; size--;
      InitNameString(s,p,slen); 
      size -= slen;
      p    += slen;
      if(OptDebug)
         printf("         |%s|%02X |%04X|\n",s,typ,mask); 
   }
   if(OptDebug)
      printf("         +----------------------------------------+---+----+\n");      
}

void DebugInfoLog(tOmfRec *omf)
{
   char s[255];
   unsigned char  sv;
   unsigned short idx;
   unsigned char  typ;
   unsigned short value;
   unsigned char  res;   
   unsigned char  slen;
   
   unsigned size    = omf->Len-1; // -chk
   unsigned char *p = &omf->Content[0];
   if(OptDebug)
   {
      printf("   Dbg : +----------------------------------------+---+----+---+----+---+\n");
      printf("         |                                        |svb|exId|typ|val |res|\n");
   }
   sv = *p++; size--;
   while (size)
   {
      idx = *p++; size --;
      if (omf->Typ & 0x01)//OMF2
      {
         idx = idx + *p++ *256; size --; 
      }
      typ = *p++; size--; 
      value = *p++; size --;
      value = value + *p++ *256; size --;
      res = *p++; size--;
      slen= *p++; size--;
      InitNameString(s,p,slen); 
      size -= slen;
      p    += slen;
      if(OptDebug)
        printf("         |%s|%02X |%04X|%02X |%04X|%02X |\n",s,sv,idx,typ,value,res); 
   }
   if(OptDebug)
     printf("         +----------------------------------------+---+----+---+----+---+\n");      
   
}

void ExternInfo(tOmfRec *omf)
{
   char s[255];
   unsigned char  blk;
   unsigned short extid;
   unsigned char  sym;
   unsigned char  res;
   //unsigned short exttyp;
   unsigned char  slen;
   
   unsigned size    = omf->Len-1; // -chk
   unsigned char *p = &omf->Content[0];
   if(OptDebug)
   {
      printf("   Ext : +----------------------------------------+---+----+---+---+\n");
      printf("         |                                        |blk|exId|sym|res|\n");
   }
   while (size)
   {
      blk   = *p++; size--;
      extid = *p++; size --;
      if (omf->Typ & 0x01)//OMF2
      {
         extid = extid + *p++ *256; size --; 
      }
      sym = *p++; size--; 
      res = *p++; size--;
      slen= *p++; size --;
      InitNameString(s,p,slen); 
      size -= slen;
      p    += slen;
      if(OptDebug)
        printf("         |%s|%02X |%04X|%02X |%02X |\n",s,blk,extid,sym,res); 
   }
   if(OptDebug)
     printf("         +----------------------------------------+---+----+---+---+\n");      
}
// ii(ii) ss oooo xx ll name
void PublicInfo(tOmfRec *omf)
{
   char s[255];
   
   unsigned short pupid;
   unsigned char  sym;
   unsigned short offset;
   unsigned char  res;
   unsigned char  slen;
   
   unsigned size    = omf->Len-1; // -chk
   unsigned char *p = &omf->Content[0];
   if(OptDebug)
   {
      printf("   Pub : +----------------------------------------+----+---+----+---+\n");
      printf("         |                                        |pId |sym|offs|res|\n");
   }
   while (size)
   {
      pupid = *p++; size --;
      if (omf->Typ & 0x01)//OMF2
      {
         pupid = pupid + *p++ *256; size --; 
      }
      sym    = *p++;                       size --;
      offset = *p++; offset += *p++ * 256; size -=2;
      res    = *p++;                       size --;
      slen   = *p++;                       size --;
      InitNameString(s,p,slen); 
      size -= slen;
      p    += slen;
      if ((sym & 0x07)==0) // code symbol
      {
         PatRecord.PubEntries[PatRecord.numPublics].Offset = offset;
         memcpy(PatRecord.PubEntries[PatRecord.numPublics].PubName,s,slen);
         PatRecord.PubEntries[PatRecord.numPublics].PubName[slen]= '\0';
         PatRecord.numPublics++;
      } 
      if(OptDebug) 
        printf("         |%s|%04X|%02X |%04X|%02X |\n",s,pupid,sym,offset,res);
   }
   if(OptDebug)
      printf("         +----------------------------------------+----+---+----+---+\n");
}

void CodeInfo(tOmfRec *omf)
{
   unsigned short codidx;
   unsigned short offset;
   //unsigned ncodes;          
   unsigned char *code; 
   
   unsigned size    = omf->Len-1;       // omit -chk
   unsigned char *p = &omf->Content[0];

   
   codidx = *p++; size --;
   if (omf->Typ & 0x01)//OMF2
   {
      codidx = codidx + *p++ *256; size --; 
   }
   offset = *p++; offset += *p++ * 256; size -=2;
   if(OptDebug)
   {
      printf("   Cod : +----+----+------------------------------\n");
      printf("         |cId |offs|data (%04X)\n",size);
      printf("         |%04X|%04X|",codidx,offset);
   }
   code = (PatRecord.CodeLen !=0) ? &PatRecord.Code[PatRecord.CodeLen*2] 
                                  : &PatRecord.Code[0];
   PatRecord.CodeLen+=size;
   while (size)
   {     
      sprintf (code,"%02X",*p);
      code +=2;
      if(OptDebug)
        printf("%02X",*p); size--;
      p++;   
   }
   if (PatRecord.CodeLen < 32 )
   {
      PatRecord.Code[PatRecord.CodeLen*2]='.';
      PatRecord.Code [64] = '\0';
   }
   if(OptDebug)
      printf("\n         +----+----+------------------------------\n");
}

void FixupInfo(tOmfRec *omf)
{

   unsigned short refloc;
   unsigned char  reftyp;
   unsigned char  opblk;
   unsigned short opid;
   unsigned short opoffset;
   unsigned short fixup;
   unsigned char  *code;
   unsigned size    = omf->Len-1; // -chk
   unsigned char *p = &omf->Content[0];
   if(OptDebug)
   {
      printf("   Fix : +----+---+---+----+----+\n");
      printf("         |rLoc|typ|blk|opId|offs|\n");
   }
   while (size)
   {
      refloc = *p++; refloc += *p++ * 256; size -=2;
      reftyp = *p++; size--;
      opblk  = *p++; size--;
      opid   = *p++; size --;
      if (omf->Typ & 0x01)//OMF2
      {
         opid = opid + *p++ *256; size --;
      }
      opoffset = *p++; opoffset += *p++ * 256; size -=2;
      if(OptDebug)
         printf("         |%04X|%02X |%02X |%04X|%04X|\n",refloc,reftyp,opblk,opid,opoffset);
      fixup= 2* (refloc+ PatRecord.Fixup);

      code = &PatRecord.Code[fixup];
      switch (reftyp)
      {
         case 0x00: //LOW
         case 0x01: //Byte
         case 0x02: //char  -128 .. +127 
         case 0x03: //high
         case 0x06: //bit   0..127    
              *code++ ='.';
              *code++ ='.';
              break;
         case 0x04://word
              *code++ ='.';
              *code++ ='.';
              *code++ ='.';
              *code++ ='.';
              break;
         case 0x05: //inblock 
              code+=2;
              *code++ ='.';
              *code++ ='.';
              break;
         default:
              printf ("unhandled %d typ\n",reftyp);
      }
   }
   PatRecord.Fixup=PatRecord.CodeLen;
   if(OptDebug)
      printf("         +----+---+---+----+----+\n");
}
// the place to write the pat file
void LogModulEnd(tOmfRec *omf)
{
   int i;
   unsigned char patstr[2*MAXCONTENT];
   
   if (PatRecord.CodeLen < (unsigned short) OptCode) return;
   if (PatRecord.numPublics==0)     return;
 
   memcpy (patstr,PatRecord.Code,64);                     // get the first 32 bytes
   patstr[64] = '\0';
   sprintf(&patstr[64]," 00 0000 %04X",PatRecord.CodeLen);//add he const vals and len      
   fprintf(outfile,"%s",patstr);

   if (PatRecord.numPublics > 1) SortPuplics();
    
   if ((PatRecord.PubEntries[0].Offset != 0)) fprintf (outfile," :0000 ?"); //  add a dummy entry    
   for ( i=0 ;i < PatRecord.numPublics ;i++) 
   {
      fprintf (outfile," :%04X %s",PatRecord.PubEntries[i].Offset,PatRecord.PubEntries[i].PubName);
   }
   if (PatRecord.CodeLen <= 32) fprintf(outfile,"\n"); //done when code fits in the first 32 bytes
   else
   {
      memcpy (patstr,&PatRecord.Code[2*32],2*(PatRecord.CodeLen -32));
      patstr[2*(PatRecord.CodeLen -32)] = '\0';
      fprintf(outfile," %s\n",patstr);
   }
   NumRecords++;
}

void LogLibHeader(tOmfRec omf)
{
   unsigned short val;
   unsigned offset;
   val = omf.Content[0] + 256*omf.Content[1];
   printf("  Modcount: 0x%04X; ",val);
   val = omf.Content[2] + 256*omf.Content[3];
   printf("Blocks: 0x%04X; ",val);
   printf("Bytes: 0x%02X; ",omf.Content[4]);
   offset = val * 0x80 +omf.Content[4];
   printf("Offset: 0x%X\n",offset);
}

void LogModStart (FILE *file,tOmfRec *omf)
{
   char modname[255];   
   InitPatRecord(); // do a fresh start
   memcpy(&modname[0],&omf->Content[1],omf->Content[0]);
   modname[omf->Content[0]]= '\0';
   if(OptDebug)
     printf("Modulname: %s\n",modname);
   while (omf->Typ != 0x04)
   {
      ReadOmfRec(file,omf);
      switch(omf->Typ)
      {
         case 0x0E:
         case 0x0F:
              SegmentInfo(omf);
              break;
         case 0x18:
         case 0x19:
              ExternInfo(omf);
              break;
         case 0x16:
         case 0x17: 
              PublicInfo(omf);
              break;
         case 0x06:
         case 0x07: 
              CodeInfo(omf);
              break;
         case 0x08:              
         case 0x09: 
              FixupInfo(omf);
              break;  
         case 0x10:         
              HeaderInfo(omf);
              break;
         case 0x12:
         case 0x22:	
         case 0x23:
              DebugInfoLog(omf);
              break;   
         case 0x72:
              RegMaskInfo(omf);
              break;         
         case 0x04:
              LogModulEnd(omf);
              break;
         default:
              printf("  ->unhandled 0x%02X\n",omf->Typ);
      }
   } 
}

void CmdLineHelp(void)
{
   printf("convert OMF51 libraries to pat files used by IDA flirt.\n");
   printf("The tool will also handle OMF2 records found in Keil C51 libs\n");
   printf("\nUsage  : omf2pat [-options] -fLibFile[.lib]\n");
   printf("         -c10 include code parts > 10 bytes.\n");
   printf("         -d do debug output on console.\n");
   printf("\nExample: omf2pat -c6 -d -fc51s > log.txt\n");
}

// a simple demo main
int main(int argc, char *argv[])
{
   int  i;
   char option;   
   tOmfRec omf;
   char inName [256];
   char outName[256];
   char s[256];
   unsigned char  b;
   unsigned short w;
   OptCode = 6;
   inName[0]='\0'; outName[0]='\0';
   
   printf ("OMF51 to PAT converter\n");
   if (argc==1) 
   {
   	  CmdLineHelp(); 
   	  return 0;
   }
   
   for (i=1; i < argc; i++)
   {
      if ((*argv[i]=='-') || (*argv[i]=='/'))
      {  /* all params start with - or / */
         argv[i]++;
         option = toupper (*argv[i]++);
         switch (option)
         {
            case 'C': //set minimum code to add
                 OptCode= strtol(argv[i],NULL,0);
                 if (OptCode < 6) OptCode = 6;
                 break;
            case 'D': //switch debug output on
                 OptDebug =1;
                 break;
            case 'F':  
                 strcpy(inName,argv[i]);
                 if(strstr(inName,".")==NULL)
                 {  
                    strcpy(outName,inName);
                    strcat(inName,".lib");
                 } 
                 else
                 {
                    strcpy(outName,inName);
                    *strstr(outName,".") = '\0';
                 }
                 strcat(outName,".pat");  
                 break;  
         }
      }   
   }

   if(inName[0]=='\0')
   {
      printf("Error: no Inputfile given!");
      return -1; 
   }  
   
   infile  = fopen(inName,"rb");
   outfile = fopen(outName,"wt");
   if(infile== NULL)  
   {
      printf("Error: file <%s> not found!",inName);
      return -2;
   }  
   if(outfile== NULL)  
   {
      printf("Error: file <%s> can't be created!",outName);
      return -2;
   }  

   ReadOmfRec(infile,&omf);
   if (omf.Typ!=0x2C)
   {
      printf("Warning: not a OMF51 lib file!\n");
      printf("Typ: 0x%02X ",omf.Typ);
      OptDebug =1;
      DebugInfo(&omf);
   }  

   while (feof(infile)==0)
   {
      ReadOmfRec(infile,&omf);
      switch (omf.Typ)
      {
         case 0x02:
              LogModStart (infile,&omf);
              break;
         case 0x26:
         case 0x28:
         case 0x2A:
         	    break;		
         default:
              printf("unhandled Typ: 0x%02X ",omf.Typ);
              DebugInfo(&omf);           
      }
   } 
   fclose(infile);
   fprintf(outfile,"---\n");
   fclose(outfile);
   printf("  %d records processed.\n",NumRecords); 
   printf("done\n");
   return 0;  
}