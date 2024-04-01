
// https://www.hulft.com/help/ja-jp/DM-V3/COM-REF/Content/DM3_JA_REF/ChapAppB/Conv_EBCDIC_ASCII_SJIS_EUC.htm
// https://factory.6-inc.com/system-develop/office-computer-data-conversion/
// http://offcom.jp/modules/amanual/index.php/ouyou/mojicode/moji_code12.html
// http://www.infonet.co.jp/ueyama/ip/binary/x0208txt.html


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <memory.h>


unsigned char ebc2ascii[256];
unsigned char hdr[32 * 1024 +10 +10];

void dump(int cnt, unsigned char *buf, int reclen)
{
	int i;
	unsigned char knj1, knj2;

	// ダンプ
	printf("H%4d : ", cnt);
	for(i=0; i<reclen; i++) {
		if ((i+1) % 10 == 0 && i>0) printf("%02X-", buf[i]);
		else printf("%02X ", buf[i]);
	}
	printf("\n");

	// 1バイト表示
	printf("A%4d : ", cnt);
	for(i=0; i<reclen; i++) {
		printf("%c", ebc2ascii[buf[i]]);
	}
	printf("\n");

	// 2バイト表示
	printf("K%4d : ", cnt);
	for(i=0; i<reclen; i++) {
		
		knj1 = buf[i];
		knj2 = buf[i+1];

		if (knj1 == 0x40 && knj2 == 0x40) {
			printf("%c", ebc2ascii[0x40]);
			printf("%c", ebc2ascii[0x40]);
			continue;
		}

		if (knj1 < 0xa1 || knj1 > 0xcf) {
			printf(".");
			continue;
		}
		i++;
		if (knj2 < 0xa1 || knj2 > 0xfe) {
			printf("..");
			continue;
		}
		
		if( knj1 & 0x01 ){
			knj1 >>= 1;
			if( knj1 < 0x6F ) knj1 += 0x31; else knj1 += 0x71;
			if( knj2 > 0xDF ) knj2 -= 0x60; else knj2 -= 0x61;
		}else{
			knj1 >>= 1;
			if( knj1 < 0x6F ) knj1 += 0x30; else knj1 += 0x70;
			knj2 -= 0x02;
		}
		printf("%c%c", knj1, knj2);
		
		
	}

	printf("\n");
}


void dump_from_file(FILE *fpi, int reclen)
{
	unsigned char buf[32 * 1024 +1];
	int sz;
	int cnt;
	int i;
	unsigned char knj1, knj2;

	cnt = 1;
	while(1) {
		sz = fread(buf, reclen, 1, fpi);
		if (feof(fpi) != 0) break;

		if ((cnt-1) % 10 == 0) printf("x%4d : %s\n", cnt, hdr);
		dump(cnt, buf, reclen);

		cnt++;
	}
}

void dump_from_stdin()
{
	unsigned char inbuf[1024*4+1], *p;
	unsigned char buf[1024*2+1];
	int c, c1, c2;
	int low = 0;
	int idx = 0;
	
	while(1) {
		if (NULL == fgets(inbuf, 1024*4, stdin)) break;
		for(p = inbuf; *p != '\0'; p++) {
			c = -1;
			if (*p >= '0' && *p <= '9') c = *p - '0';
			else if (*p >= 'a' && *p <= 'f') c = *p - 'a' + 10;
			else if (*p >= 'A' && *p <= 'F') c = *p - 'A' + 10;
			else {
				low = 0;
				continue;
			}
			if (low == 0) {
				c1 = c;
				low = 1;
			} else {
				c2 = c;
				buf[idx] = c1 * 16 + c2;
				idx++;
				low = 0;
			}
		}
		dump(0, buf, idx);
		printf("\n");
		idx = 0;
		low = 0;
	}

	return;
}


int main(int argc, char *argv[])
{
	unsigned char *infile_path;
	int reclen;

	ebc2ascii[0] = 0x2e;
	ebc2ascii[1]=0x2E;
	ebc2ascii[2]=0x2E;
	ebc2ascii[3]=0x2E;
	ebc2ascii[4]=0x2E;
	ebc2ascii[5]=0x2E;
	ebc2ascii[6]=0x2E;
	ebc2ascii[7]=0x2E;
	ebc2ascii[8]=0x2E;
	ebc2ascii[9]=0x2E;
	ebc2ascii[10]=0x2E;
	ebc2ascii[11]=0x2E;
	ebc2ascii[12]=0x2E;
	ebc2ascii[13]=0x2E;
	ebc2ascii[14]=0x2E;
	ebc2ascii[15]=0x2E;
	ebc2ascii[16]=0x2E;
	ebc2ascii[17]=0x2E;
	ebc2ascii[18]=0x2E;
	ebc2ascii[19]=0x2E;
	ebc2ascii[20]=0x2E;
	ebc2ascii[21]=0x2E;
	ebc2ascii[22]=0x2E;
	ebc2ascii[23]=0x2E;
	ebc2ascii[24]=0x2E;
	ebc2ascii[25]=0x2E;
	ebc2ascii[26]=0x2E;
	ebc2ascii[27]=0x2E;
	ebc2ascii[28]=0x2E;
	ebc2ascii[29]=0x2E;
	ebc2ascii[30]=0x2E;
	ebc2ascii[31]=0x2E;
	ebc2ascii[32]=0x2E;
	ebc2ascii[33]=0x2E;
	ebc2ascii[34]=0x2E;
	ebc2ascii[35]=0x2E;
	ebc2ascii[36]=0x2E;
	ebc2ascii[37]=0x2E;
	ebc2ascii[38]=0x2E;
	ebc2ascii[39]=0x2E;
	ebc2ascii[40]=0x2E;
	ebc2ascii[41]=0x2E;
	ebc2ascii[42]=0x2E;
	ebc2ascii[43]=0x2E;
	ebc2ascii[44]=0x2E;
	ebc2ascii[45]=0x2E;
	ebc2ascii[46]=0x2E;
	ebc2ascii[47]=0x2E;
	ebc2ascii[48]=0x2E;
	ebc2ascii[49]=0x2E;
	ebc2ascii[50]=0x2E;
	ebc2ascii[51]=0x2E;
	ebc2ascii[52]=0x2E;
	ebc2ascii[53]=0x2E;
	ebc2ascii[54]=0x2E;
	ebc2ascii[55]=0x2E;
	ebc2ascii[56]=0x2E;
	ebc2ascii[57]=0x2E;
	ebc2ascii[58]=0x2E;
	ebc2ascii[59]=0x2E;
	ebc2ascii[60]=0x2E;
	ebc2ascii[61]=0x2E;
	ebc2ascii[62]=0x2E;
	ebc2ascii[63]=0x2E;
	ebc2ascii[64]=0x20;
	ebc2ascii[65]=0xA1;
	ebc2ascii[66]=0xA2;
	ebc2ascii[67]=0xA3;
	ebc2ascii[68]=0xA4;
	ebc2ascii[69]=0xA5;
	ebc2ascii[70]=0xA6;
	ebc2ascii[71]=0xA7;
	ebc2ascii[72]=0xA8;
	ebc2ascii[73]=0xA9;
	ebc2ascii[74]=0x5B;
	ebc2ascii[75]=0x2E;
	ebc2ascii[76]=0x3C;
	ebc2ascii[77]=0x28;
	ebc2ascii[78]=0x2B;
	ebc2ascii[79]=0x7C;
	ebc2ascii[80]=0x26;
	ebc2ascii[81]=0xAA;
	ebc2ascii[82]=0xAB;
	ebc2ascii[83]=0xAC;
	ebc2ascii[84]=0xAD;
	ebc2ascii[85]=0xAE;
	ebc2ascii[86]=0xAF;
	ebc2ascii[87]=0x2E;
	ebc2ascii[88]=0xB0;
	ebc2ascii[89]=0x2E;
	ebc2ascii[90]=0x21;
	ebc2ascii[91]=0x24;
	ebc2ascii[92]=0x2A;
	ebc2ascii[93]=0x29;
	ebc2ascii[94]=0x3B;
	ebc2ascii[95]=0x5E;
	ebc2ascii[96]=0x2D;
	ebc2ascii[97]=0x2F;
	ebc2ascii[98]=0x2E;
	ebc2ascii[99]=0x2E;
	ebc2ascii[100]=0x2E;
	ebc2ascii[101]=0x2E;
	ebc2ascii[102]=0x2E;
	ebc2ascii[103]=0x2E;
	ebc2ascii[104]=0x2E;
	ebc2ascii[105]=0x2E;
	ebc2ascii[106]=0x7C;
	ebc2ascii[107]=0x2C;
	ebc2ascii[108]=0x25;
	ebc2ascii[109]=0x5F;
	ebc2ascii[110]=0x3E;
	ebc2ascii[111]=0x3F;
	ebc2ascii[112]=0x2E;
	ebc2ascii[113]=0x2E;
	ebc2ascii[114]=0x2E;
	ebc2ascii[115]=0x2E;
	ebc2ascii[116]=0x2E;
	ebc2ascii[117]=0x2E;
	ebc2ascii[118]=0x2E;
	ebc2ascii[119]=0x2E;
	ebc2ascii[120]=0x2E;
	ebc2ascii[121]=0x60;
	ebc2ascii[122]=0x3A;
	ebc2ascii[123]=0x23;
	ebc2ascii[124]=0x40;
	ebc2ascii[125]=0x27;
	ebc2ascii[126]=0x3D;
	ebc2ascii[127]=0x22;
	ebc2ascii[128]=0x2E;
	ebc2ascii[129]=0xB1;
	ebc2ascii[130]=0xB2;
	ebc2ascii[131]=0xB3;
	ebc2ascii[132]=0xB4;
	ebc2ascii[133]=0xB5;
	ebc2ascii[134]=0xB6;
	ebc2ascii[135]=0xB7;
	ebc2ascii[136]=0xB8;
	ebc2ascii[137]=0xB9;
	ebc2ascii[138]=0xBA;
	ebc2ascii[139]=0x2E;
	ebc2ascii[140]=0xBB;
	ebc2ascii[141]=0xBC;
	ebc2ascii[142]=0xBD;
	ebc2ascii[143]=0xBE;
	ebc2ascii[144]=0xBF;
	ebc2ascii[145]=0xC0;
	ebc2ascii[146]=0xC1;
	ebc2ascii[147]=0xC2;
	ebc2ascii[148]=0xC3;
	ebc2ascii[149]=0xC4;
	ebc2ascii[150]=0xC5;
	ebc2ascii[151]=0xC6;
	ebc2ascii[152]=0xC7;
	ebc2ascii[153]=0xC8;
	ebc2ascii[154]=0xC9;
	ebc2ascii[155]=0x2E;
	ebc2ascii[156]=0x2E;
	ebc2ascii[157]=0xCA;
	ebc2ascii[158]=0xCB;
	ebc2ascii[159]=0xCC;
	ebc2ascii[160]=0x2E;
	ebc2ascii[161]=0x7E;
	ebc2ascii[162]=0xCD;
	ebc2ascii[163]=0xCE;
	ebc2ascii[164]=0xCF;
	ebc2ascii[165]=0xD0;
	ebc2ascii[166]=0xD1;
	ebc2ascii[167]=0xD2;
	ebc2ascii[168]=0xD3;
	ebc2ascii[169]=0xD4;
	ebc2ascii[170]=0xD5;
	ebc2ascii[171]=0x2E;
	ebc2ascii[172]=0xD6;
	ebc2ascii[173]=0xD7;
	ebc2ascii[174]=0xD8;
	ebc2ascii[175]=0xD9;
	ebc2ascii[176]=0x2E;
	ebc2ascii[177]=0x2E;
	ebc2ascii[178]=0x2E;
	ebc2ascii[179]=0x2E;
	ebc2ascii[180]=0x2E;
	ebc2ascii[181]=0x2E;
	ebc2ascii[182]=0x2E;
	ebc2ascii[183]=0x2E;
	ebc2ascii[184]=0x2E;
	ebc2ascii[185]=0x2E;
	ebc2ascii[186]=0xDA;
	ebc2ascii[187]=0xDB;
	ebc2ascii[188]=0xDC;
	ebc2ascii[189]=0xDD;
	ebc2ascii[190]=0xDE;
	ebc2ascii[191]=0xDF;
	ebc2ascii[192]=0x7B;
	ebc2ascii[193]=0x41;
	ebc2ascii[194]=0x42;
	ebc2ascii[195]=0x43;
	ebc2ascii[196]=0x44;
	ebc2ascii[197]=0x45;
	ebc2ascii[198]=0x46;
	ebc2ascii[199]=0x47;
	ebc2ascii[200]=0x48;
	ebc2ascii[201]=0x49;
	ebc2ascii[202]=0x2E;
	ebc2ascii[203]=0x2E;
	ebc2ascii[204]=0x2E;
	ebc2ascii[205]=0x2E;
	ebc2ascii[206]=0x2E;
	ebc2ascii[207]=0x2E;
	ebc2ascii[208]=0x7D;
	ebc2ascii[209]=0x4A;
	ebc2ascii[210]=0x4B;
	ebc2ascii[211]=0x4C;
	ebc2ascii[212]=0x4D;
	ebc2ascii[213]=0x4E;
	ebc2ascii[214]=0x4F;
	ebc2ascii[215]=0x50;
	ebc2ascii[216]=0x51;
	ebc2ascii[217]=0x52;
	ebc2ascii[218]=0x2E;
	ebc2ascii[219]=0x2E;
	ebc2ascii[220]=0x2E;
	ebc2ascii[221]=0x2E;
	ebc2ascii[222]=0x2E;
	ebc2ascii[223]=0x2E;
	ebc2ascii[224]=0x5C;
	ebc2ascii[225]=0x2E;
	ebc2ascii[226]=0x53;
	ebc2ascii[227]=0x54;
	ebc2ascii[228]=0x55;
	ebc2ascii[229]=0x56;
	ebc2ascii[230]=0x57;
	ebc2ascii[231]=0x58;
	ebc2ascii[232]=0x59;
	ebc2ascii[233]=0x5A;
	ebc2ascii[234]=0x2E;
	ebc2ascii[235]=0x2E;
	ebc2ascii[236]=0x2E;
	ebc2ascii[237]=0x2E;
	ebc2ascii[238]=0x2E;
	ebc2ascii[239]=0x2E;
	ebc2ascii[240]=0x30;
	ebc2ascii[241]=0x31;
	ebc2ascii[242]=0x32;
	ebc2ascii[243]=0x33;
	ebc2ascii[244]=0x34;
	ebc2ascii[245]=0x35;
	ebc2ascii[246]=0x36;
	ebc2ascii[247]=0x37;
	ebc2ascii[248]=0x38;
	ebc2ascii[249]=0x39;
	ebc2ascii[250]=0x2E;
	ebc2ascii[251]=0x2E;
	ebc2ascii[252]=0x2E;
	ebc2ascii[253]=0x2E;
	ebc2ascii[254]=0x2E;
	ebc2ascii[255]=0x2E;

	if (argc < 3) {
		dump_from_stdin();
		return 0;
	}
	
	reclen = atoi(argv[1]);
	infile_path = argv[2];
	
	
    FILE *fpi;
	
	if (NULL == (fpi = fopen(infile_path, "rb"))) {
		perror("file open error");
		exit(1);
	}

	memset(hdr, '-', 32 * 1024 +10);
	unsigned char colstr[8];
	int i;
	for(i=10; i<=reclen+9; i+=10) {
		if (i+10 > reclen +9) {
			sprintf(&(hdr[i-1]), "%d", i);
			continue;
		}
		sprintf(colstr, "%d", i);
		memcpy(&(hdr[i-1]), colstr, strlen(colstr));
	}
	
	dump_from_file(fpi, reclen);
	
	fclose(fpi);
	return 0;
}


